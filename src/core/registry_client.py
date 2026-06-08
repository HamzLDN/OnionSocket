import json
import socket
import threading
import time

from src.core import tcp_enhancer
from src.core.protocol import (
    DEFAULT_HOST,
    DEFAULT_REGISTRY_PORT,
    REGISTRY_HEARTBEAT,
    REGISTRY_HEARTBEAT_INTERVAL,
    REGISTRY_LIST,
    REGISTRY_REGISTER,
)


def _connect(registry_host, registry_port, timeout=2.0):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    sock.connect((registry_host, registry_port))
    tcp_enhancer.set_nodelay(sock)
    return sock


def register_service(
    *,
    service_type,
    host,
    port,
    public_key_pem,
    registry_host=DEFAULT_HOST,
    registry_port=DEFAULT_REGISTRY_PORT,
    timeout=2.0,
):
    payload = {
        "type": service_type,
        "host": host,
        "port": port,
        "public_key": public_key_pem.decode("utf-8"),
    }
    coms = tcp_enhancer.coms()
    with _connect(registry_host, registry_port, timeout) as sock:
        coms.send(sock, REGISTRY_REGISTER)
        coms.send(sock, json.dumps(payload).encode("utf-8"))


def send_heartbeat(
    *,
    service_type,
    host,
    port,
    registry_host=DEFAULT_HOST,
    registry_port=DEFAULT_REGISTRY_PORT,
    timeout=2.0,
):
    payload = {"type": service_type, "host": host, "port": port}
    coms = tcp_enhancer.coms()
    with _connect(registry_host, registry_port, timeout) as sock:
        coms.send(sock, REGISTRY_HEARTBEAT)
        coms.send(sock, json.dumps(payload).encode("utf-8"))


def list_services(
    registry_host=DEFAULT_HOST,
    registry_port=DEFAULT_REGISTRY_PORT,
    timeout=2.0,
):
    coms = tcp_enhancer.coms()
    with _connect(registry_host, registry_port, timeout) as sock:
        coms.send(sock, REGISTRY_LIST)
        raw = coms.recv(sock)
    if not raw:
        raise RuntimeError(
            f"registry at {registry_host}:{registry_port} returned no data"
        )
    data = json.loads(raw.decode("utf-8"))
    nodes = []
    for item in data.get("nodes", []):
        node = {
            "host": item["host"],
            "port": int(item["port"]),
        }
        pem = item.get("public_key")
        if pem:
            node["public_key_pem"] = pem.encode("utf-8")
        nodes.append(node)
    nodes.sort(key=lambda item: (item["host"], item["port"]))

    servers = []
    for item in data.get("servers", []):
        entry = {
            "host": item["host"],
            "port": int(item["port"]),
        }
        pem = item.get("public_key")
        if pem:
            entry["public_key_pem"] = pem.encode("utf-8")
        servers.append(entry)
    servers.sort(key=lambda item: (item["host"], item["port"]))
    return nodes, servers


def start_registration_loop(
    *,
    service_type,
    host,
    port,
    public_key_pem,
    registry_host=DEFAULT_HOST,
    registry_port=DEFAULT_REGISTRY_PORT,
):
    def loop():
        while True:
            try:
                register_service(
                    service_type=service_type,
                    host=host,
                    port=port,
                    public_key_pem=public_key_pem,
                    registry_host=registry_host,
                    registry_port=registry_port,
                )
                print(f"Registered with directory {registry_host}:{registry_port}")
                while True:
                    time.sleep(REGISTRY_HEARTBEAT_INTERVAL)
                    send_heartbeat(
                        service_type=service_type,
                        host=host,
                        port=port,
                        registry_host=registry_host,
                        registry_port=registry_port,
                    )
            except Exception as e:
                print(f"Directory retry: {e}")
                time.sleep(5)

    threading.Thread(target=loop, daemon=True).start()


def maybe_register(
    *,
    enabled,
    service_type,
    host,
    port,
    public_key_pem,
    registry_host,
    registry_port,
):
    if not enabled:
        return
    start_registration_loop(
        service_type=service_type,
        host=host,
        port=port,
        public_key_pem=public_key_pem,
        registry_host=registry_host,
        registry_port=registry_port,
    )
