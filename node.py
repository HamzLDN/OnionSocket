import argparse

from src.core.protocol import (
    DEFAULT_BIND_HOST,
    DEFAULT_HOST,
    DEFAULT_REGISTRY_PORT,
)
from src.node.relay import RelayNode

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="OnionSocket relay node")
    parser.add_argument("--host", default=DEFAULT_BIND_HOST)
    parser.add_argument("--advertise-host", default=None)
    parser.add_argument("--port", type=int, default=10001)
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--registry-host", default=DEFAULT_HOST)
    parser.add_argument("--registry-port", type=int, default=DEFAULT_REGISTRY_PORT)
    parser.add_argument("--no-registry", action="store_true")
    parser.add_argument(
        "--plain",
        action="store_true",
        help="plain text logs instead of the dashboard",
    )
    args = parser.parse_args()

    node = RelayNode(
        host=args.host,
        port=args.port,
        verbose=args.verbose,
        advertise_host=args.advertise_host,
        registry_host=args.registry_host,
        registry_port=args.registry_port,
        register=not args.no_registry,
        quiet=not args.plain,
    )
    if args.plain:
        node.start()
    else:
        node.run_with_dashboard()
