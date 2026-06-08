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
    nodes=MIN_RELAY_NODES,
    min_nodes=MIN_RELAY_NODES,
    secure=True,
    registry_host=None,
    registry_port=DEFAULT_REGISTRY_PORT,
    use_registry=True,
    insecure=False,
    use_all=False,
    scan=False,
    scan_host=None,
    scan_start=DEFAULT_SCAN_START,
    scan_end=DEFAULT_SCAN_END,
) -> Scattered:
    remote = network_host or server_host
    if server_host is None and remote is not None:
        server_host = remote
    if registry_host is None:
        registry_host = remote or DEFAULT_HOST
    if scan_host is None:
        scan_host = remote or DEFAULT_HOST
    return Scattered(
        secure=secure and not insecure,
        num_nodes=nodes,
        min_nodes=min_nodes,
        use_all=use_all,
        registry_host=registry_host,
        registry_port=registry_port,
        use_registry=use_registry and not scan,
        server_host=server_host,
        server_port=server_port,
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
    parser.add_argument("--server-host", default=None)
    parser.add_argument("--server-port", type=int, default=None)
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
