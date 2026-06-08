import random
import socket

from src.core import tcp_enhancer
from src.core.asymmetric import rsa
from src.core.protocol import (
    DEFAULT_HOST,
    DEFAULT_REGISTRY_PORT,
    DEFAULT_SCAN_END,
    DEFAULT_SCAN_START,
    MIN_RELAY_NODES,
    PROBE,
    PROBE_KEY,
)
from src.core.registry_client import list_services


def probe_port(host, port, timeout=0.3):
    coms = tcp_enhancer.coms()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((host, port))
        coms.send(sock, PROBE)
        reply = coms.recv(sock)
        if not reply:
            return None
        if reply.startswith(b"RELAY:") or reply.startswith(b"NODE:"):
            return ("node", int(reply.split(b":", 1)[1]))
        if reply.startswith(b"EXIT:") or reply.startswith(b"SERVER:"):
            return ("server", int(reply.split(b":", 1)[1]))
    except OSError:
        return None
    finally:
        sock.close()
    return None


def fetch_pubkey(host, port, timeout=0.5):
    coms = tcp_enhancer.coms()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((host, port))
        coms.send(sock, PROBE_KEY)
        pem = coms.recv(sock)
        if not pem:
            raise RuntimeError(f"no public key from {host}:{port}")
        if pem.startswith((b"RELAY:", b"NODE:", b"EXIT:", b"SERVER:")):
            raise RuntimeError(f"{host}:{port}: probe tag, not a key")
        if not pem.startswith(b"-----BEGIN"):
            raise RuntimeError(f"invalid key from {host}:{port}")
        rsa.load_public_key(pem)
        return pem
    finally:
        sock.close()


def fetch_node_pubkey(host, port, timeout=0.5):
    return fetch_pubkey(host, port, timeout)


def fetch_server_pubkey(host, port, timeout=0.5):
    return fetch_pubkey(host, port, timeout)


def enrich_chain_with_pubkeys(chain):
    enriched = []
    for node in chain:
        pem = node.get("public_key_pem") or fetch_node_pubkey(node["host"], node["port"])
        enriched.append({**node, "public_key": rsa.load_public_key(pem), "public_key_pem": pem})
    return enriched


def enrich_server_with_pubkey(server):
    pem = server.get("public_key_pem") or fetch_server_pubkey(
        server["host"], server["port"]
    )
    return {**server, "public_key": rsa.load_public_key(pem), "public_key_pem": pem}


def fetch_from_registry(
    registry_host=DEFAULT_HOST,
    registry_port=DEFAULT_REGISTRY_PORT,
    timeout=2.0,
):
    nodes, servers = list_services(registry_host, registry_port, timeout)
    server = servers[0] if servers else None
    return nodes, server


def _merge_nodes(*lists):
    seen = set()
    merged = []
    for nodes in lists:
        for node in nodes:
            key = (node["host"], node["port"])
            if key in seen:
                continue
            seen.add(key)
            merged.append(node)
    merged.sort(key=lambda item: (item["host"], item["port"]))
    return merged


def _probe_hosts(host, prefer_host=None):
    hosts = []
    for candidate in (prefer_host, "localhost", "127.0.0.1", host, DEFAULT_HOST):
        if candidate and candidate not in hosts:
            hosts.append(candidate)
    return hosts


def filter_live_relays(nodes, *, prefer_host=None):
    by_port: dict[int, set[str]] = {}
    for node in nodes:
        by_port.setdefault(int(node["port"]), set()).add(node["host"])

    live = []
    for port in sorted(by_port):
        registered = by_port[port]
        for host in _probe_hosts(next(iter(registered)), prefer_host):
            result = probe_port(host, port)
            if result and result[0] == "node":
                live.append({"host": host, "port": result[1]})
                break
    return live


def resolve_live_exit(server, *, prefer_host=None):
    if server is None:
        return None
    port = int(server["port"])
    for host in _probe_hosts(server["host"], prefer_host):
        result = probe_port(host, port)
        if result and result[0] == "server":
            return {"host": host, "port": result[1]}
    return None


def dedupe_nodes_by_port(nodes, prefer_host=None):
    return filter_live_relays(nodes, prefer_host=prefer_host)


def discover_network(
    *,
    registry_host=DEFAULT_HOST,
    registry_port=DEFAULT_REGISTRY_PORT,
    use_registry=True,
    scan_host=DEFAULT_HOST,
    scan_start=DEFAULT_SCAN_START,
    scan_end=DEFAULT_SCAN_END,
):
    reg_nodes, reg_server = [], None
    if use_registry:
        try:
            reg_nodes, reg_server = fetch_from_registry(registry_host, registry_port)
        except (OSError, RuntimeError):
            pass
    scan_nodes, scan_server = scan_network(scan_host, scan_start, scan_end)
    nodes = filter_live_relays(
        _merge_nodes(reg_nodes, scan_nodes),
        prefer_host=scan_host,
    )
    server = (
        resolve_live_exit(reg_server, prefer_host=scan_host)
        or resolve_live_exit(scan_server, prefer_host=scan_host)
    )
    return nodes, server


def format_network_listing(nodes, server):
    lines = []
    if nodes:
        lines.append("Active relay nodes:")
        for node in nodes:
            lines.append(f"  - {node['host']}:{node['port']}")
    else:
        lines.append("Active relay nodes: none")
    if server:
        lines.append(f"Exit node: {server['host']}:{server['port']}")
    else:
        lines.append("Exit node: none")
    return "\n".join(lines)


def scan_network(
    host=DEFAULT_HOST,
    start=DEFAULT_SCAN_START,
    end=DEFAULT_SCAN_END,
):
    nodes = []
    server = None

    for port in range(start, end + 1):
        result = probe_port(host, port)
        if not result:
            continue
        kind, found_port = result
        if kind == "node":
            nodes.append({"host": host, "port": found_port})
        elif kind == "server" and server is None:
            server = {"host": host, "port": found_port}

    nodes.sort(key=lambda item: item["port"])
    return nodes, server


def _chain_count(nodes, server, num_nodes, min_nodes, use_all):
    if server is None:
        raise RuntimeError("no exit node found on the network")
    count = len(nodes) if use_all else (num_nodes if num_nodes is not None else min_nodes)
    if count < min_nodes:
        raise RuntimeError(f"need at least {min_nodes} relay nodes")
    if len(nodes) < count:
        found = ", ".join(f"{n['host']}:{n['port']}" for n in nodes) or "none"
        raise RuntimeError(
            f"need {count} relay nodes, found {len(nodes)} ({found}). "
            "Start at least 3 relays (e.g. node.py --port 10001/10002/10003)."
        )
    return count


def select_relay_chain(
    nodes,
    server,
    *,
    num_nodes=None,
    min_nodes=MIN_RELAY_NODES,
    use_all=False,
):
    count = _chain_count(nodes, server, num_nodes, min_nodes, use_all)
    chosen = list(nodes) if use_all else nodes[:count]
    return chosen[0], chosen[1:], server


def select_random_relay_chain(
    nodes,
    server,
    *,
    num_nodes=None,
    min_nodes=MIN_RELAY_NODES,
    use_all=False,
):
    count = _chain_count(nodes, server, num_nodes, min_nodes, use_all)
    chain = random.sample(nodes, count)
    return chain, chain[0], chain[1:], server
