#!/usr/bin/env python3
from src.server import (
    ClientDisconnected,
    accept,
    close,
    create,
    format_sessions,
    listen,
    receive,
    send,
)


def main():
    srv = create(port=10004, quiet=True)
    listen(srv)
    print(f"Server started on port {srv.port}")
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
