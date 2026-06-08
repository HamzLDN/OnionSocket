#!/usr/bin/env python3
from src import client


def main():
    s = client.create(nodes=3)

    try:
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
