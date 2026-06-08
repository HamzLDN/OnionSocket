import argparse

from src.core.protocol import (
    DEFAULT_BIND_HOST,
    DEFAULT_HOST,
    DEFAULT_REGISTRY_PORT,
)
from src.node.exit import ExitNode
from src.server import (
    ClientDisconnected,
    accept,
    close,
    listen,
    receive,
    send,
)

if __name__ == "__main__":
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
    parser.add_argument(
        "--plain",
        action="store_true",
        help="plain text logs instead of the dashboard",
    )
    args = parser.parse_args()

    node = ExitNode(
        host=args.host,
        port=args.port,
        verbose=args.verbose,
        secure=not args.insecure,
        echo=args.echo,
        advertise_host=args.advertise_host,
        registry_host=args.registry_host,
        registry_port=args.registry_port,
        register=not args.no_registry,
        quiet=not args.plain,
    )

    if args.plain:
        listen(node)
        try:
            while True:
                conn = accept(node)
                try:
                    message = receive(node, conn)
                    if message is None:
                        continue
                    print(f"[client] {message.decode('utf-8', errors='replace')}")
                    send(node, conn, message)
                except ClientDisconnected as e:
                    print(e)
                finally:
                    close(conn)
        except KeyboardInterrupt:
            print("\nShutting down exit node...")
            node.close()
    else:
        node.run_with_dashboard(
            echo_handler=lambda conn, message: node.send(conn, message)
        )
