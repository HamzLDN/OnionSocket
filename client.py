#!/usr/bin/env python3
from src import client
from src.core.discovery import format_network_listing


def main():
    # server_port = the port your server.py (or exit.py) is running on
    s = client.create(
        network_host="192.168.0.2",
        server_port=10004,
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


if __name__ == "__main__":
    main()
