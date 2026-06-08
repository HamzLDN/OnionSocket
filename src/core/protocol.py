import socket

RELAY = b"\x22"
PROBE = b"\x23"
PROBE_KEY = b"\x24"
CLIENT_ONION = b"\x25"
CLIENT_CLOSE = b"\x26"
REGISTRY_REGISTER = b"\x30"
REGISTRY_LIST = b"\x31"
REGISTRY_HEARTBEAT = b"\x32"

SERVICE_RELAY = "relay"
SERVICE_EXIT = "exit"
SERVICE_NODE = SERVICE_RELAY
SERVICE_SERVER = SERVICE_EXIT

DEFAULT_BIND_HOST = "0.0.0.0"
DEFAULT_HOST = "localhost"
DEFAULT_REGISTRY_PORT = 10000
DEFAULT_SCAN_START = 10001
DEFAULT_SCAN_END = 10020
MIN_RELAY_NODES = 3
REGISTRY_TTL_SECONDS = 45
REGISTRY_HEARTBEAT_INTERVAL = 15
REGISTRY_REGISTER_INTERVAL = 5
REGISTRY_RETRY_INTERVAL = 3
CONNECT_TIMEOUT = 3.0
PROBE_TIMEOUT = 0.25
RECV_TIMEOUT = 30.0


def resolve_advertise_host(bind_host, advertise_host=None):
    if advertise_host:
        return advertise_host
    if bind_host not in ("0.0.0.0", "::"):
        return bind_host
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect(("8.8.8.8", 80))
        ip = sock.getsockname()[0]
        sock.close()
        return ip
    except OSError:
        return "127.0.0.1"
