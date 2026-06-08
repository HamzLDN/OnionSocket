import socket
import threading

from src.core import tcp_enhancer
from src.core.asymmetric import rsa
from src.core.onion import HOP_SERVER, format_peel_report, peel_layer
from src.core.protocol import (
    CLIENT_ONION,
    DEFAULT_BIND_HOST,
    DEFAULT_HOST,
    DEFAULT_REGISTRY_PORT,
    PROBE,
    PROBE_KEY,
    RELAY,
    SERVICE_RELAY,
    resolve_advertise_host,
)
from src.core.registry_client import maybe_register
from src.node.dashboard import NodeDashboard
from src.node.stats import NodeStats


class NextHop:
    def __init__(self, ip, port):
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.host = (ip, port)
        self.coms = tcp_enhancer.coms()

    def connect(self):
        self.client_socket.connect(self.host)
        return True

    def send(self, msg):
        self.coms.send(self.client_socket, msg)

    def recv(self):
        return self.coms.recv(self.client_socket)

    def close(self):
        self.client_socket.close()


class RelayNode:
    def __init__(
        self,
        host=DEFAULT_BIND_HOST,
        port=10001,
        verbose=False,
        *,
        advertise_host=None,
        registry_host=DEFAULT_HOST,
        registry_port=DEFAULT_REGISTRY_PORT,
        register=True,
        quiet=False,
        stats: NodeStats | None = None,
    ):
        self.advertise_host = resolve_advertise_host(host, advertise_host)
        self.port = port
        self.verbose = verbose
        self.quiet = quiet
        self.registry_host = registry_host
        self.registry_port = registry_port
        self.stats = stats or NodeStats(
            role="relay",
            advertise_host=self.advertise_host,
            port=port,
            registry=f"{registry_host}:{registry_port}" if register else "",
            mode="onion forward",
        )
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((host, port))
        self.server_socket.listen(5)
        self.coms = tcp_enhancer.coms()
        self.private_key, self.public_key = rsa.generate_rsa_keys()
        if not quiet:
            print(f"Relay node {self.advertise_host}:{port}")
        self.stats.event(f"Relay node online at {self.advertise_host}:{port}")
        maybe_register(
            enabled=register,
            service_type=SERVICE_RELAY,
            host=self.advertise_host,
            port=port,
            public_key_pem=rsa.export_public_key(self.public_key),
            registry_host=registry_host,
            registry_port=registry_port,
        )
        if register:
            self.stats.event(f"Registering with directory {registry_host}:{registry_port}")

    def _track_recv(self, sock, conn_id: int | None):
        data = self.coms.recv(sock)
        if data is not None:
            self.stats.record_in(self.stats.wire_len(data), conn_id)
        return data

    def _track_send(self, sock, msg, conn_id: int | None):
        self.coms.send(sock, msg)
        self.stats.record_out(self.stats.wire_len(msg), conn_id)

    def next_node(self, sock, next_hop, conn_id: int):
        while True:
            try:
                data = self._track_recv(sock, conn_id)
                if data is None:
                    sock.close()
                    next_hop.close()
                    break
                next_hop.send(data)
                self.stats.record_out(self.stats.wire_len(data), conn_id)
            except Exception:
                break

    def back_node(self, sock, next_hop, conn_id: int):
        while True:
            try:
                data = next_hop.recv()
                if data is None:
                    next_hop.close()
                    sock.close()
                    break
                self.stats.record_in(self.stats.wire_len(data), conn_id)
                self._track_send(sock, data, conn_id)
            except Exception:
                break

    def start_forwarding(self, client_sock, next_hop, conn_id: int):
        threading.Thread(
            target=self.next_node,
            args=(client_sock, next_hop, conn_id),
            daemon=True,
        ).start()
        threading.Thread(
            target=self.back_node,
            args=(client_sock, next_hop, conn_id),
            daemon=True,
        ).start()

    def log_peel(self, hop_type, host, port, inner):
        if hop_type == HOP_SERVER:
            kind = "exit"
        else:
            kind = "relay"
        self.stats.note_peel()
        self.stats.event(f"Peel -> {host}:{port} ({kind})")
        if not self.verbose:
            return
        print(format_peel_report(self.port, hop_type, host, port, inner))

    def connect_from_layer(self, client_sock, layer_blob, conn_id: int):
        hop_type, host, port, inner = peel_layer(self.private_key, layer_blob)
        self.log_peel(hop_type, host, port, inner)

        next_hop = NextHop(host, port)
        try:
            next_hop.connect()
        except OSError as e:
            target = "exit" if hop_type == HOP_SERVER else "relay"
            self.stats.event(f"Next hop unreachable ({target}) {host}:{port}: {e}")
            sock.close()
            self.stats.close_connection(conn_id)
            return

        if hop_type == HOP_SERVER:
            if inner:
                next_hop.send(inner)
                self.stats.record_out(self.stats.wire_len(inner), conn_id)
        else:
            next_hop.send(RELAY)
            self.stats.record_out(self.stats.wire_len(RELAY), conn_id)
            next_hop.send(inner)
            self.stats.record_out(self.stats.wire_len(inner), conn_id)

        self.start_forwarding(client_sock, next_hop, conn_id)

    def handle_onion_client(self, sock, conn_id: int):
        onion_blob = self._track_recv(sock, conn_id)
        if onion_blob is None:
            sock.close()
            self.stats.close_connection(conn_id)
            return
        self.connect_from_layer(sock, onion_blob, conn_id)

    def handle_relay(self, sock, conn_id: int):
        inner_blob = self._track_recv(sock, conn_id)
        if inner_blob is None:
            sock.close()
            self.stats.close_connection(conn_id)
            return
        self.connect_from_layer(sock, inner_blob, conn_id)

    def handle_connection(self, sock, addr):
        conn_id = self.stats.open_connection(addr, "pending")
        try:
            first = self._track_recv(sock, conn_id)
            if first is None:
                sock.close()
                self.stats.close_connection(conn_id)
                return

            if first == PROBE:
                reply = f"RELAY:{self.port}".encode()
                self._track_send(sock, reply, conn_id)
                self.stats.note_probe()
                self.stats.event(f"Probe from {addr[0]}:{addr[1]}")
                sock.close()
                self.stats.close_connection(conn_id)
                return

            if first == PROBE_KEY:
                pem = rsa.export_public_key(self.public_key)
                self._track_send(sock, pem, conn_id)
                self.stats.event(f"Key request from {addr[0]}:{addr[1]}")
                sock.close()
                self.stats.close_connection(conn_id)
                return

            if first == CLIENT_ONION:
                self.stats.set_connection_kind(conn_id, "onion")
                self.stats.note_client_circuit()
                self.stats.event(f"Onion circuit from {addr[0]}:{addr[1]}")
                self.handle_onion_client(sock, conn_id)
                return

            if first == RELAY:
                self.stats.set_connection_kind(conn_id, "relay")
                self.stats.note_relay_hop()
                self.stats.event(f"Relay hop from {addr[0]}:{addr[1]}")
                self.handle_relay(sock, conn_id)
                return

            sock.close()
            self.stats.close_connection(conn_id)
        except Exception as e:
            self.stats.event(f"Connection error: {e}")
            if not self.quiet:
                print(f"connection error: {e}")
            sock.close()
            self.stats.close_connection(conn_id)

    def start(self, stop_event: threading.Event | None = None):
        self.server_socket.settimeout(1.0)
        try:
            while stop_event is None or not stop_event.is_set():
                try:
                    client_socket, addr = self.server_socket.accept()
                except socket.timeout:
                    continue
                except OSError:
                    break
                threading.Thread(
                    target=self.handle_connection,
                    args=(client_socket, addr),
                    daemon=True,
                ).start()
        except KeyboardInterrupt:
            if not self.quiet:
                print("\nShutting down relay node...")
        finally:
            self.server_socket.close()

    def run_with_dashboard(self):
        stop_event = threading.Event()
        threading.Thread(target=self.start, args=(stop_event,), daemon=True).start()
        NodeDashboard(self.stats, stop_event).run()
        stop_event.set()
        self.server_socket.close()
        if not self.quiet:
            print("Relay node stopped.")
