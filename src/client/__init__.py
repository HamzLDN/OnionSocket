#!/usr/bin/env python3
import argparse

from src.client.scattered import Scattered
from src.core.protocol import (
    DEFAULT_HOST,
    DEFAULT_REGISTRY_PORT,
    DEFAULT_SCAN_END,
    DEFAULT_SCAN_START,
    MIN_RELAY_NODES,
)

__all__ = ["Scattered", "create", "send", "receive", "close"]


def create(
    *,
    server_host=None,
    server_port=None,
    network_host=None,
    exit_port=None,
    nodes=None,
    min_nodes=MIN_RELAY_NODES,
    secure=True,
    registry_host=None,
    registry_port=DEFAULT_REGISTRY_PORT,
    use_registry=True,
    insecure=False,
    use_all=True,
    scan=False,
    scan_host=None,
    scan_start=DEFAULT_SCAN_START,
    scan_end=DEFAULT_SCAN_END,
) -> Scattered:
    # server_host/server_port = the destination server the client wants to reach.
    # It is encrypted inside the onion; only the exit decrypts it and connects.
    # The exit itself is discovered from the registry (optionally pinned via exit_port).
    remote = network_host or server_host
    if registry_host is None:
        registry_host = remote or DEFAULT_HOST
    if scan_host is None:
        scan_host = remote or DEFAULT_HOST
    dest_host = server_host or remote
    return Scattered(
        secure=secure and not insecure,
        num_nodes=nodes,
        min_nodes=min_nodes,
        use_all=use_all,
        registry_host=registry_host,
        registry_port=registry_port,
        use_registry=use_registry and not scan,
        dest_host=dest_host,
        dest_port=server_port,
        exit_port=exit_port,
        scan_host=scan_host,
        scan_start=scan_start,
        scan_end=scan_end,
    )


def send(sock: Scattered, data: bytes) -> list[bytes]:
    return sock.send(data)


def receive(sock: Scattered, timeout=None) -> bytes | None:
    return sock.receive(timeout=timeout)


def close(sock: Scattered):
    sock.close()


def from_args(args) -> Scattered:
    return create(
        network_host=args.network_host,
        server_host=args.server_host,
        server_port=args.server_port,
        exit_port=args.exit_port,
        nodes=args.nodes or args.min_nodes,
        min_nodes=args.min_nodes,
        insecure=args.insecure,
        use_all=args.use_all,
        registry_host=args.registry_host,
        registry_port=args.registry_port,
        scan=args.scan,
        scan_host=args.scan_host,
        scan_start=args.scan_start,
        scan_end=args.scan_end,
    )


def main():
    parser = argparse.ArgumentParser(description="OnionSocket client")
    parser.add_argument("--min-nodes", type=int, default=MIN_RELAY_NODES)
    parser.add_argument("--nodes", type=int, default=MIN_RELAY_NODES)
    parser.add_argument("--use-all", action="store_true")
    parser.add_argument("--insecure", action="store_true")
    parser.add_argument(
        "--network-host",
        default=None,
        help="remote machine running registry, relays, and exit (LAN IP)",
    )
    parser.add_argument("--registry-host", default=None)
    parser.add_argument("--registry-port", type=int, default=DEFAULT_REGISTRY_PORT)
    parser.add_argument(
        "--server-host", default=None, help="destination server host (reached via the exit)"
    )
    parser.add_argument(
        "--server-port", type=int, default=None, help="destination server port"
    )
    parser.add_argument(
        "--exit-port",
        type=int,
        default=None,
        help="optionally pin which exit (from the registry) to route through",
    )
    parser.add_argument("--scan", action="store_true")
    parser.add_argument("--scan-host", default=DEFAULT_HOST)
    parser.add_argument("--scan-start", type=int, default=DEFAULT_SCAN_START)
    parser.add_argument("--scan-end", type=int, default=DEFAULT_SCAN_END)
    parser.add_argument("--send", help="send one message and print replies")
    args = parser.parse_args()

    if (args.server_host is None) ^ (args.server_port is None):
        parser.error("use --server-host and --server-port together")

    sock = from_args(args)

    if args.send:
        for reply in sock.send(args.send.encode("utf-8")):
            try:
                print(reply.decode("utf-8"))
            except UnicodeDecodeError:
                print(repr(reply))
        return

    parser.error("pass --send or use client.py for chat")


if __name__ == "__main__":
    main()
