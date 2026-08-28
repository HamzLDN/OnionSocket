#!/usr/bin/env python3
"""OnionSocket client — chat demo or local web proxy."""

import argparse

from src import client
from src.core.discovery import format_network_listing
from src.core.protocol import DEFAULT_HOST, DEFAULT_REGISTRY_PORT


def run_proxy(args):
    from src.proxy.local_proxy import run_local_proxy

    remote = args.network_host or DEFAULT_HOST
    s = client.create(
        network_host=remote,
        registry_host=args.registry_host or remote,
        registry_port=args.registry_port,
        exit_port=args.exit_port,
        nodes=args.nodes,
        min_nodes=args.min_nodes,
        use_all=args.use_all,
        insecure=True,
    )
    run_local_proxy(
        s,
        host=args.proxy_host,
        port=args.proxy_port,
        verbose=args.verbose,
    )


def run_chat():
    s = client.create(
        network_host="localhost",
        server_host="localhost",
        server_port=10005,
    )

    try:
        nodes, server = s.prepare_network()
        print(format_network_listing(nodes, server))
        print(f"Using {len(nodes)} live relays per circuit (random order each message)")
        print()
        for text in ("hello", "second message"):
            print(f"You: {text}")
            replies = client.send(s, text.encode("utf-8"))
            for reply in replies:
                print(f"Server: {reply.decode('utf-8', errors='replace')}")
            if not replies:
                print("Server: (no reply)")
    finally:
        client.close(s)
        print("Connection closed")


def main():
    parser = argparse.ArgumentParser(description="OnionSocket client")
    parser.add_argument(
        "--proxy",
        action="store_true",
        help="run local HTTP proxy for web browsing through the onion network",
    )
    parser.add_argument("--proxy-host", default="127.0.0.1")
    parser.add_argument("--proxy-port", type=int, default=8080)
    parser.add_argument("--network-host", default=None, help="LAN IP of onion network")
    parser.add_argument("--registry-host", default=None)
    parser.add_argument("--registry-port", type=int, default=DEFAULT_REGISTRY_PORT)
    parser.add_argument("--exit-port", type=int, default=None)
    parser.add_argument("--nodes", type=int, default=3)
    parser.add_argument("--min-nodes", type=int, default=3)
    parser.add_argument("--use-all", action="store_true")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    if args.proxy:
        run_proxy(args)
    else:
        run_chat()


if __name__ == "__main__":
    main()
