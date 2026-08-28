import argparse
import socket

from src.core import tcp_enhancer
from src.core.protocol import (
    CONNECT_TIMEOUT,
    DEFAULT_BIND_HOST,
    DEFAULT_HOST,
    DEFAULT_REGISTRY_PORT,
    RECV_TIMEOUT,
)
from src.node.exit import ExitNode
from src.proxy.exit_stream import relay_stream, serve_connection
from src.server import (
    ClientDisconnected,
    accept,
    close,
    listen,
)

_coms = tcp_enhancer.coms()


def forward_to_destination(dest_host, dest_port, message):
    """Connect to the destination the client chose (decrypted from the onion)
    and return its reply."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(CONNECT_TIMEOUT)
        sock.connect((dest_host, int(dest_port)))
        tcp_enhancer.set_nodelay(sock)
        sock.settimeout(RECV_TIMEOUT)
        _coms.send(sock, message)
        reply = _coms.recv(sock)
    return reply


def reply_for(conn, message, *, echo=False, verbose=False):
    if echo:
        return message
    dest = getattr(conn, "dest", None)
    if not dest or not dest[0]:
        return b"[exit: client did not specify a destination]"
    dest_host, dest_port = dest
    if verbose:
        print(f"[exit] decrypted destination {dest_host}:{dest_port}")
    try:
        reply = forward_to_destination(dest_host, dest_port, message)
    except OSError as e:
        print(f"[exit] cannot reach destination {dest_host}:{dest_port}: {e}")
        return f"[exit: destination {dest_host}:{dest_port} unreachable]".encode()
    if reply is None:
        return b"[exit: destination closed without reply]"
    return reply


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="OnionSocket exit node")
    parser.add_argument("--host", default=DEFAULT_BIND_HOST)
    parser.add_argument("--advertise-host", default=None)
    parser.add_argument("--port", type=int, default=10004)
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--insecure", action="store_true")
    parser.add_argument(
        "--echo",
        action="store_true",
        help="echo messages back instead of connecting to the client's destination",
    )
    parser.add_argument("--registry-host", default=DEFAULT_HOST)
    parser.add_argument("--registry-port", type=int, default=DEFAULT_REGISTRY_PORT)
    parser.add_argument("--no-registry", action="store_true")
    parser.add_argument(
        "--plain",
        action="store_true",
        help="plain text logs instead of the dashboard",
    )
    parser.add_argument(
        "--no-proxy",
        action="store_true",
        help="disable web streaming (chat/message mode only)",
    )
    args = parser.parse_args()

    proxy_enabled = not args.no_proxy

    node = ExitNode(
        host=args.host,
        port=args.port,
        verbose=args.verbose,
        secure=not args.insecure and not proxy_enabled,
        echo=False,
        advertise_host=args.advertise_host,
        registry_host=args.registry_host,
        registry_port=args.registry_port,
        register=not args.no_registry,
        quiet=not args.plain,
    )

    def handle(conn):
        serve_connection(
            node,
            conn,
            verbose=args.verbose,
            echo=args.echo,
            reply_for=reply_for,
        )

    if args.plain:
        listen(node)
        print(f"Exit node listening on {node.host}:{node.port}")
        if proxy_enabled:
            print("Web proxy enabled: streams empty-body circuits; relays messages otherwise.")
        else:
            print("Message mode only (web streaming disabled).")
        try:
            while True:
                conn = accept(node)
                try:
                    handle(conn)
                except ClientDisconnected as e:
                    print(e)
                finally:
                    close(conn)
        except KeyboardInterrupt:
            print("\nShutting down exit node...")
            node.close()
    else:
        node.run_with_dashboard(
            stream_handler=handle if proxy_enabled else None,
            echo_handler=None if proxy_enabled else (
                lambda conn, message: node.send(
                    conn, reply_for(conn, message, echo=args.echo, verbose=args.verbose)
                )
            ),
        )
