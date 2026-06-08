#!/usr/bin/env python3
import argparse
import json
import socket
import threading
import time

from src.core import tcp_enhancer
from src.core.protocol import (
    DEFAULT_BIND_HOST,
    DEFAULT_REGISTRY_PORT,
    REGISTRY_HEARTBEAT,
    REGISTRY_LIST,
    REGISTRY_REGISTER,
    REGISTRY_TTL_SECONDS,
    SERVICE_EXIT,
    SERVICE_RELAY,
)

__all__ = ["Directory", "create", "listen"]


class Directory:
    def __init__(
        self,
        host=DEFAULT_BIND_HOST,
        port=DEFAULT_REGISTRY_PORT,
        *,
        verbose=False,
    ):
        self.host = host
        self.port = port
        self.verbose = verbose
        self.coms = tcp_enhancer.coms()
        self.entries = {}
        self.lock = threading.Lock()
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((host, port))
        self.server_socket.listen(20)
        self._running = False
        self._log(f"Directory ready on {host}:{port}")

    def _log(self, message: str):
        stamp = time.strftime("%H:%M:%S")
        print(f"[{stamp}] {message}")

    def _format_peer(self, addr):
        if not addr:
            return "unknown"
        return f"{addr[0]}:{addr[1]}"

    def close(self):
        self._running = False
        self.server_socket.close()

    def listen(self):
        self._running = True
        self._log(f"Listening on {self.host}:{self.port}")
        while self._running:
            client_socket, addr = self.server_socket.accept()
            threading.Thread(
                target=self._handle_connection_safe,
                args=(client_socket, addr),
                daemon=True,
            ).start()

    def _key(self, service_type, host, port):
        return (service_type, host, int(port))

    def _prune_stale(self):
        now = time.time()
        stale = [
            key
            for key, entry in self.entries.items()
            if now - entry["last_seen"] > REGISTRY_TTL_SECONDS
        ]
        for key in stale:
            entry = self.entries[key]
            self._log(
                f"Expired {entry['type']} {entry['host']}:{entry['port']} "
                f"(no heartbeat for {REGISTRY_TTL_SECONDS}s)"
            )
            del self.entries[key]

    def _normalize_type(self, service_type):
        if service_type in ("node", SERVICE_RELAY):
            return SERVICE_RELAY
        if service_type in ("server", SERVICE_EXIT):
            return SERVICE_EXIT
        raise ValueError(f"unknown service type: {service_type!r}")

    def register(self, payload):
        service_type = self._normalize_type(payload.get("type"))
        host = payload["host"]
        port = int(payload["port"])
        public_key = payload.get("public_key")
        key = self._key(service_type, host, port)
        with self.lock:
            is_new = key not in self.entries
            if service_type == SERVICE_EXIT:
                stale = [
                    entry_key
                    for entry_key, entry in self.entries.items()
                    if entry["type"] == SERVICE_EXIT
                    and entry["host"] == host
                    and entry["port"] != port
                ]
                for entry_key in stale:
                    del self.entries[entry_key]
            self.entries[key] = {
                "type": service_type,
                "host": host,
                "port": port,
                "public_key": public_key,
                "last_seen": time.time(),
            }
        # Nodes re-register periodically to stay alive and to self-heal across
        # directory restarts; only log the first time we see one (or in verbose
        # mode) so the steady-state refreshes don't spam the log.
        if is_new:
            self._log(f"Registered {service_type} {host}:{port}")
        elif self.verbose:
            self._log(f"Refreshed {service_type} {host}:{port}")

    def heartbeat(self, payload, *, peer=None):
        service_type = self._normalize_type(payload.get("type"))
        host = payload["host"]
        port = int(payload["port"])
        key = self._key(service_type, host, port)
        with self.lock:
            if key in self.entries:
                self.entries[key]["last_seen"] = time.time()
                if self.verbose:
                    self._log(
                        f"Heartbeat {service_type} {host}:{port} "
                        f"from {self._format_peer(peer)}"
                    )
            elif self.verbose:
                self._log(
                    f"Heartbeat for unknown {service_type} {host}:{port} "
                    f"from {self._format_peer(peer)}"
                )

    def list_active(self):
        with self.lock:
            self._prune_stale()
            nodes = []
            servers = []
            for entry in self.entries.values():
                item = {
                    "host": entry["host"],
                    "port": entry["port"],
                    "public_key": entry.get("public_key"),
                }
                if entry["type"] == SERVICE_RELAY:
                    nodes.append(item)
                else:
                    servers.append(item)
        nodes.sort(key=lambda item: (item["host"], item["port"]))
        servers.sort(key=lambda item: (item["host"], item["port"]))
        return {"nodes": nodes, "servers": servers}

    def _log_listing(self, listing, *, peer=None):
        nodes = listing["nodes"]
        servers = listing["servers"]
        relay_ports = ", ".join(str(item["port"]) for item in nodes) or "none"
        exit_ports = ", ".join(str(item["port"]) for item in servers) or "none"
        self._log(
            f"List request from {self._format_peer(peer)} -> "
            f"{len(nodes)} relay(s) [{relay_ports}], "
            f"{len(servers)} exit(s) [{exit_ports}]"
        )

    def handle_connection(self, sock, addr=None):
        tag = self.coms.recv(sock)
        if tag is None:
            return
        if tag == REGISTRY_REGISTER:
            raw = self.coms.recv(sock)
            if raw:
                payload = json.loads(raw.decode("utf-8"))
                self.register(payload)
                if self.verbose:
                    self._log(
                        f"Register request from {self._format_peer(addr)} "
                        f"for {payload.get('type')} {payload.get('host')}:{payload.get('port')}"
                    )
            return
        if tag == REGISTRY_HEARTBEAT:
            raw = self.coms.recv(sock)
            if raw:
                self.heartbeat(json.loads(raw.decode("utf-8")), peer=addr)
            return
        if tag == REGISTRY_LIST:
            listing = self.list_active()
            self._log_listing(listing, peer=addr)
            payload = json.dumps(listing).encode("utf-8")
            self.coms.send(sock, payload)
            return
        self._log(f"Unknown request tag {tag!r} from {self._format_peer(addr)}")

    def _handle_connection_safe(self, sock, addr):
        try:
            self.handle_connection(sock, addr)
        except Exception as e:
            self._log(f"Connection error from {self._format_peer(addr)}: {e}")
        finally:
            sock.close()

    def start(self):
        try:
            self.listen()
        except KeyboardInterrupt:
            print("\nShutting down directory...")
            self.close()


def create(
    *,
    host=DEFAULT_BIND_HOST,
    port=DEFAULT_REGISTRY_PORT,
    verbose=False,
) -> Directory:
    return Directory(host=host, port=port, verbose=verbose)


def listen(directory: Directory):
    directory.start()


def from_args(args) -> Directory:
    return create(host=args.host, port=args.port, verbose=args.verbose)


def main():
    parser = argparse.ArgumentParser(description="OnionSocket directory server")
    parser.add_argument("--host", default=DEFAULT_BIND_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_REGISTRY_PORT)
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="log heartbeats and register request sources",
    )
    args = parser.parse_args()
    listen(from_args(args))


if __name__ == "__main__":
    main()
