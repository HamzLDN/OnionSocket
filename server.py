#!/usr/bin/env python3
import argparse

from src.core.protocol import DEFAULT_HOST, DEFAULT_REGISTRY_PORT
from src.server import (
    ClientDisconnected,
    accept,
    close,
    create_exit_node,
    format_sessions,
    listen,
    receive,
    send,
)


def main():
    parser = argparse.ArgumentParser(
        description="OnionSocket server (the destination your client reaches through the onion circuit)"
    )
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--advertise-host", default=None)
    parser.add_argument("--port", type=int, default=10004)
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--registry-host", default=DEFAULT_HOST)
    parser.add_argument("--registry-port", type=int, default=DEFAULT_REGISTRY_PORT)
    parser.add_argument("--no-registry", action="store_true")
    args = parser.parse_args()

    srv = create_exit_node(
        host=args.host,
        port=args.port,
        verbose=args.verbose,
        advertise_host=args.advertise_host,
        registry_host=args.registry_host,
        registry_port=args.registry_port,
        register=not args.no_registry,
        quiet=True,
    )
    listen(srv)
    print(f"Listening on {srv.host}:{srv.port}")
    if srv.host in ("0.0.0.0", "::"):
        print(f"Reachable at {srv.advertise_host}:{srv.port}")
    while True:
        conn = accept(srv)
        print(f"Connection #{conn.conn_id} from {conn.addr[0]}:{conn.addr[1]}")

        try:
            message = receive(srv, conn)
            if message is None:
                continue

            if conn.session is None:
                print(f"[unknown] {message.decode('utf-8', errors='replace')}")
            elif conn.session_is_new:
                print(f"New session {conn.session.label}")
                print(
                    f"[{conn.session.label}] {message.decode('utf-8', errors='replace')}"
                )
            else:
                print(
                    f"[{conn.session.label}] {message.decode('utf-8', errors='replace')}"
                )

            print(format_sessions(srv))
            send(srv, conn, message)
        except ClientDisconnected as e:
            if conn.session is not None:
                print(f"{conn.session.label} disconnected ({e})")
            else:
                print(e)
            print(format_sessions(srv))
        finally:
            close(conn)


if __name__ == "__main__":
    main()
