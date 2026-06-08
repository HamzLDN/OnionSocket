#!/usr/bin/env python3
import argparse

from src.core.protocol import DEFAULT_BIND_HOST, DEFAULT_HOST, DEFAULT_REGISTRY_PORT
from src.node.exit import ExitNode
from src.server.exit_server import (
    ClientConnection,
    ClientDisconnected,
    ClientSession,
    ExitServer,
)

__all__ = [
    "ExitNode",
    "ExitServer",
    "ClientConnection",
    "ClientSession",
    "ClientDisconnected",
    "create",
    "create_exit_node",
    "listen",
    "accept",
    "receive",
    "send",
    "close",
    "queue",
    "list_sessions",
    "get_session",
    "format_sessions",
]


def create(
    *,
    host=DEFAULT_BIND_HOST,
    port=10005,
    verbose=False,
    secure=True,
    echo=False,
    advertise_host=None,
    registry_host=DEFAULT_HOST,
    registry_port=DEFAULT_REGISTRY_PORT,
    register=False,
    quiet=False,
) -> ExitServer:
    """Socket-style application server (not the onion exit by default)."""
    return ExitServer(
        host=host,
        port=port,
        verbose=verbose,
        secure=secure,
        echo=echo,
        advertise_host=advertise_host,
        registry_host=registry_host,
        registry_port=registry_port,
        register=register,
        is_exit_node=False,
        quiet=quiet,
    )


def create_exit_node(
    *,
    host=DEFAULT_BIND_HOST,
    port=10004,
    verbose=False,
    secure=True,
    echo=False,
    advertise_host=None,
    registry_host=DEFAULT_HOST,
    registry_port=DEFAULT_REGISTRY_PORT,
    register=True,
    quiet=False,
) -> ExitNode:
    """Core onion exit node."""
    return ExitNode(
        host=host,
        port=port,
        verbose=verbose,
        secure=secure,
        echo=echo,
        advertise_host=advertise_host,
        registry_host=registry_host,
        registry_port=registry_port,
        register=register,
        quiet=quiet,
    )


def listen(server: ExitServer, backlog=5):
    server.listen(backlog)


def accept(server: ExitServer) -> ClientConnection:
    return server.accept()


def receive(server: ExitServer, conn: ClientConnection) -> bytes | None:
    return server.receive(conn)


def send(server: ExitServer, conn: ClientConnection, data=None):
    server.send(conn, data)


def close(conn: ClientConnection):
    conn.close()


def list_sessions(server: ExitServer) -> list[ClientSession]:
    return server.list_sessions()


def get_session(server: ExitServer, *, sid=None, public_key=None, client_id=None):
    return server.get_session(sid=sid, public_key=public_key, client_id=client_id)


def format_sessions(server: ExitServer) -> str:
    return server.format_sessions()


def queue(
    server: ExitServer,
    text: str,
    *,
    session=None,
    sid=None,
    public_key=None,
    client_id=None,
):
    server.queue(
        text,
        session=session,
        sid=sid,
        public_key=public_key,
        client_id=client_id,
    )


def from_args(args, *, as_exit=False) -> ExitServer:
    factory = create_exit_node if as_exit else create
    return factory(
        host=args.host,
        port=args.port,
        verbose=args.verbose,
        secure=not args.insecure,
        echo=args.echo,
        advertise_host=args.advertise_host,
        registry_host=args.registry_host,
        registry_port=args.registry_port,
        register=not args.no_registry,
    )


def main():
    parser = argparse.ArgumentParser(description="OnionSocket exit node")
    parser.add_argument("--host", default=DEFAULT_BIND_HOST)
    parser.add_argument("--advertise-host", default=None)
    parser.add_argument("--port", type=int, default=10004)
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--insecure", action="store_true")
    parser.add_argument("--echo", action="store_true")
    parser.add_argument("--registry-host", default=DEFAULT_HOST)
    parser.add_argument("--registry-port", type=int, default=DEFAULT_REGISTRY_PORT)
    parser.add_argument("--no-registry", action="store_true")
    args = parser.parse_args()

    srv = create_exit_node(
        host=args.host,
        port=args.port,
        verbose=args.verbose,
        secure=not args.insecure,
        echo=args.echo,
        advertise_host=args.advertise_host,
        registry_host=args.registry_host,
        registry_port=args.registry_port,
        register=not args.no_registry,
    )
    listen(srv)
    try:
        while True:
            conn = accept(srv)
            try:
                message = receive(srv, conn)
                if message is None:
                    continue
                print(f"[client] {message.decode('utf-8', errors='replace')}")
                send(srv, conn, message)
            except ClientDisconnected as e:
                print(e)
            finally:
                close(conn)
    except KeyboardInterrupt:
        print("\nShutting down...")
        srv.close()


if __name__ == "__main__":
    main()
