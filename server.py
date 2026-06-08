#!/usr/bin/env python3
import argparse
import socket

from src.core import tcp_enhancer

# Backend application server. The EXIT node forwards decrypted messages here;
# the client never talks to this directly. No onion, no E2E, no registry.


def main():
    parser = argparse.ArgumentParser(
        description="OnionSocket backend server (the exit forwards decrypted messages here)"
    )
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=10005)
    parser.add_argument(
        "--prefix",
        default="",
        help="optional text prepended to each reply (e.g. 'server: ')",
    )
    args = parser.parse_args()

    coms = tcp_enhancer.coms()
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((args.host, args.port))
    server_socket.listen(20)
    print(f"Backend server listening on {args.host}:{args.port}")

    conn_id = 0
    try:
        while True:
            conn, addr = server_socket.accept()
            tcp_enhancer.set_nodelay(conn)
            conn_id += 1
            try:
                message = coms.recv(conn)
                if message is None:
                    continue
                text = message.decode("utf-8", errors="replace")
                print(f"#{conn_id} from exit {addr[0]}:{addr[1]}: {text}")
                reply = (args.prefix + text).encode("utf-8") if args.prefix else message
                coms.send(conn, reply)
            finally:
                conn.close()
    except KeyboardInterrupt:
        print("\nShutting down backend server...")
        server_socket.close()


if __name__ == "__main__":
    main()
