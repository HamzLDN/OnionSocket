import os
import random
import socket
import time
from concurrent.futures import ThreadPoolExecutor

from src.core import tcp_enhancer
from src.core.asymmetric import rsa
from src.core.protocol import (
    CONNECT_TIMEOUT,
    DEFAULT_HOST,
    DEFAULT_REGISTRY_PORT,
    DEFAULT_SCAN_END,
    DEFAULT_SCAN_START,
    MIN_RELAY_NODES,
    PROBE,
    PROBE_KEY,
    PROBE_TIMEOUT,
)
from src.core.registry_client import list_services


def _is_local_host(host):
    return host in (None, "", "localhost", "127.0.0.1", "::1")


def probe_port(host, port, timeout=PROBE_TIMEOUT):
    coms = tcp_enhancer.coms()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((host, port))
        tcp_enhancer.set_nodelay(sock)
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
        tcp_enhancer.set_nodelay(sock)
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
    return nodes, servers


def pick_live_exit(servers, *, prefer_host=None, prefer_port=None):
    if not servers:
        return None
    ordered = sorted(
        servers,
        key=lambda item: (
            0 if prefer_port is not None and int(item["port"]) == prefer_port else 1,
            item["host"],
            item["port"],
        ),
    )
    for entry in ordered:
        live = resolve_live_exit(entry, prefer_host=prefer_host)
        if live:
            return live
    return None


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
    for candidate in (prefer_host, host):
        if candidate and candidate not in hosts:
            hosts.append(candidate)
    if _is_local_host(prefer_host) or _is_local_host(host):
        for candidate in ("localhost", "127.0.0.1", DEFAULT_HOST):
            if candidate not in hosts:
                hosts.append(candidate)
    return hosts


def _connect_host(prefer_host, registered_host):
    if prefer_host and not _is_local_host(prefer_host):
        return prefer_host
    return registered_host


def nodes_from_registry(nodes, *, connect_host=None):
    by_port: dict[int, dict] = {}
    for node in nodes:
        port = int(node["port"])
        if port in by_port:
            continue
        host = _connect_host(connect_host, node["host"])
        entry = {"host": host, "port": port}
        pem = node.get("public_key_pem")
        if pem:
            entry["public_key_pem"] = pem
        by_port[port] = entry
    return [by_port[port] for port in sorted(by_port)]


def _node_entry(node, *, connect_host=None):
    host = _connect_host(connect_host, node["host"])
    entry = {"host": host, "port": int(node["port"])}
    pem = node.get("public_key_pem")
    if pem:
        entry["public_key_pem"] = pem
    return entry


def keep_live_nodes(nodes, *, timeout=CONNECT_TIMEOUT):
    if not nodes:
        return []

    def check(node):
        if probe_port(node["host"], node["port"], timeout=timeout):
            return node
        return None

    workers = min(len(nodes), 16)
    with ThreadPoolExecutor(max_workers=workers) as pool:
        live = [item for item in pool.map(check, nodes) if item]
    return sorted(live, key=lambda item: item["port"])


def exit_from_registry(servers, *, connect_host=None, prefer_port=None):
    host = _connect_host(connect_host, DEFAULT_HOST)
    if prefer_port is not None:
        preferred = {"host": host, "port": int(prefer_port)}
        for pick in servers or []:
            if int(pick["port"]) == int(prefer_port) and pick.get("public_key_pem"):
                preferred["public_key_pem"] = pick["public_key_pem"]
                break
        if probe_port(preferred["host"], preferred["port"], timeout=CONNECT_TIMEOUT):
            return preferred
    if not servers:
        return None
    ordered = sorted(
        servers,
        key=lambda item: (
            0 if prefer_port is not None and int(item["port"]) == prefer_port else 1,
            int(item["port"]),
        ),
    )
    for pick in ordered:
        entry = _node_entry(pick, connect_host=connect_host)
        if probe_port(entry["host"], entry["port"], timeout=CONNECT_TIMEOUT):
            return entry
    return None


def filter_live_relays(nodes, *, prefer_host=None):
    by_port: dict[int, set[str]] = {}
    for node in nodes:
        by_port.setdefault(int(node["port"]), set()).add(node["host"])

    live = []
    for port in sorted(by_port):
        registered = by_port[port]
        for host in _probe_hosts(next(iter(registered)), prefer_host):
            result = probe_port(host, port, timeout=0.2)
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
    exit_port=None,
    use_scan=False,
):
    timing = os.environ.get("ONION_TIMING", "1") != "0"
    if use_registry:
        t0 = time.perf_counter()
        try:
            reg_nodes, reg_servers = fetch_from_registry(registry_host, registry_port)
        except (OSError, RuntimeError) as exc:
            raise RuntimeError(
                f"cannot reach directory at {registry_host}:{registry_port}"
            ) from exc
        t1 = time.perf_counter()
        nodes = keep_live_nodes(
            nodes_from_registry(reg_nodes, connect_host=scan_host)
        )
        t2 = time.perf_counter()
        server = exit_from_registry(
            reg_servers, connect_host=scan_host, prefer_port=exit_port
        )
        t3 = time.perf_counter()
        if timing:
            print(
                f"[timing] registry list {(t1 - t0) * 1000:.0f}ms, "
                f"relay live-probe {(t2 - t1) * 1000:.0f}ms ({len(reg_nodes)} listed -> {len(nodes)} live), "
                f"exit probe {(t3 - t2) * 1000:.0f}ms"
            )
        if use_scan and (len(nodes) < MIN_RELAY_NODES or server is None):
            scan_nodes, scan_server = scan_network(
                scan_host, scan_start, scan_end, timeout=0.2
            )
            nodes = filter_live_relays(
                _merge_nodes(nodes, scan_nodes),
                prefer_host=scan_host,
            )
            if server is None and scan_server:
                server = pick_live_exit(
                    [scan_server], prefer_host=scan_host, prefer_port=exit_port
                )
        return nodes, server

    if use_scan:
        scan_nodes, scan_server = scan_network(
            scan_host, scan_start, scan_end, timeout=0.2
        )
        nodes = filter_live_relays(scan_nodes, prefer_host=scan_host)
        server = None
        if scan_server:
            server = pick_live_exit(
                [scan_server], prefer_host=scan_host, prefer_port=exit_port
            )
        return nodes, server

    raise RuntimeError(
        "discovery uses the directory registry; start registry.py on the network host"
    )


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
    timeout=0.2,
):
    nodes = []
    server = None

    for port in range(start, end + 1):
        result = probe_port(host, port, timeout=timeout)
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
            "Start relays on the remote machine and point the client at that host "
            "(e.g. client.create(network_host='192.168.1.100', server_port=10004))."
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
