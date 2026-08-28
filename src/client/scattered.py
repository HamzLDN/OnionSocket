import os
import queue
import socket
import threading
import time

from src.core import tcp_enhancer
from src.core.asymmetric import rsa
from src.core.discovery import (
    discover_network,
    enrich_chain_with_pubkeys,
    enrich_server_with_pubkey,
    select_random_relay_chain,
    select_relay_chain,
)
from src.core.e2e import (
    open_client_reply,
    open_padded_client_reply,
    open_stream_data,
    pack_stream_keys,
    seal_for_server,
    seal_padded_for_server,
    seal_stream,
    is_stream_frame,
)
from src.core.symmetric import aes
from src.core.tunnel_mux import TUNNEL_DEST, TUNNEL_PORT
from src.core.onion import build_onion
from src.core.protocol import (
    CLIENT_CLOSE,
    CLIENT_ONION,
    CLIENT_STREAM,
    CONNECT_TIMEOUT,
    DEFAULT_HOST,
    DEFAULT_REGISTRY_PORT,
    DEFAULT_SCAN_END,
    DEFAULT_SCAN_START,
    MIN_RELAY_NODES,
    RECV_TIMEOUT,
)
from src.core.secure_transport import unpack_server_replies


class StreamCircuit:
    """Bidirectional stream through an onion circuit (for web proxy)."""

    def __init__(self, sock, coms, exit_pubkey, private_key, c2e_key, e2c_key):
        self._sock = sock
        self._coms = coms
        self._exit_pubkey = exit_pubkey
        self._private_key = private_key
        self._c2e_key = c2e_key
        self._e2c_key = e2c_key
        self._active = True
        self._closed = False
        self._queue = queue.Queue()
        self._thread = threading.Thread(target=self._recv_loop, daemon=True)
        self._thread.start()

    @property
    def active(self) -> bool:
        return self._active and not self._closed

    def send(self, data: bytes):
        if not data or not self.active:
            return
        framed = seal_stream(self._c2e_key, data)
        self._coms.send(self._sock, framed)

    def recv(self, timeout=None) -> bytes | None:
        try:
            return self._queue.get(timeout=timeout)
        except queue.Empty:
            return None

    def close(self):
        if self._closed:
            return
        self._closed = True
        self._active = False
        try:
            self._sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            self._sock.close()
        except OSError:
            pass

    def _recv_loop(self):
        while self._active:
            try:
                framed = self._coms.recv(self._sock)
            except OSError:
                self._active = False
                break
            if framed is None:
                self._active = False
                break
            try:
                if is_stream_frame(framed):
                    data = open_stream_data(self._e2c_key, framed)
                else:
                    data = open_client_reply(self._private_key, framed)
            except Exception:
                continue
            if data:
                self._queue.put(data)


class Scattered:
    def __init__(
        self,
        *,
        secure=True,
        num_nodes=None,
        min_nodes=MIN_RELAY_NODES,
        use_all=False,
        registry_host=DEFAULT_HOST,
        registry_port=DEFAULT_REGISTRY_PORT,
        use_registry=True,
        dest_host=None,
        dest_port=None,
        exit_port=None,
        scan_host=DEFAULT_HOST,
        scan_start=DEFAULT_SCAN_START,
        scan_end=DEFAULT_SCAN_END,
    ):
        self.secure = secure
        self.num_nodes = num_nodes
        self.min_nodes = min_nodes
        self.use_all = use_all
        self.coms = tcp_enhancer.coms()
        self.private_key, self.public_key = rsa.generate_rsa_keys()
        self.public_key_pem = rsa.export_public_key(self.public_key)
        self.registry_host = registry_host
        self.registry_port = registry_port
        self.use_registry = use_registry
        # dest_host/dest_port = the destination server the client wants to reach.
        # It is encrypted inside the onion; only the exit decrypts and connects to it.
        self.dest_host = dest_host
        self.dest_port = dest_port
        # exit_port = optionally prefer a specific exit from the registry.
        self.exit_port = exit_port
        self.scan_host = scan_host
        self.scan_start = scan_start
        self.scan_end = scan_end

        self._secure_replies = []
        self._insecure_queue = queue.Queue()
        self._sock = None
        self._server_info = None
        self._chain = None
        self._onion_sent = False
        self._recv_thread = None
        self._active = False
        self._nodes_cache = None
        self._closed = False

    def load_network(self):
        nodes, exit_node = discover_network(
            registry_host=self.registry_host,
            registry_port=self.registry_port,
            use_registry=self.use_registry,
            scan_host=self.scan_host,
            scan_start=self.scan_start,
            scan_end=self.scan_end,
            exit_port=self.exit_port,
            use_scan=not self.use_registry,
        )
        if exit_node is None:
            raise RuntimeError(
                "no exit node found in registry (start exit.py first)"
            )
        if self.exit_port is not None and int(exit_node["port"]) != self.exit_port:
            raise RuntimeError(
                f"registry has no exit on port {self.exit_port} "
                f"(found {exit_node['port']} instead — restart exit.py on {self.exit_port})"
            )
        if len(nodes) < self.min_nodes:
            raise RuntimeError(
                f"registry has {len(nodes)} relays, need at least {self.min_nodes}"
            )
        return nodes, exit_node

    def _timing(self):
        return os.environ.get("ONION_TIMING", "1") != "0"

    def prepare_network(self):
        if self._nodes_cache is not None and self._server_info is not None:
            return self._nodes_cache, self._server_info
        timing = self._timing()
        t0 = time.perf_counter()
        nodes, server = self.load_network()
        t1 = time.perf_counter()
        self._nodes_cache = enrich_chain_with_pubkeys(nodes)
        self._server_info = enrich_server_with_pubkey(server)
        t2 = time.perf_counter()
        if timing:
            print(
                f"[timing] discovery {(t1 - t0) * 1000:.0f}ms "
                f"(registry+live probes), pubkeys {(t2 - t1) * 1000:.0f}ms"
            )
        return self._nodes_cache, self._server_info

    def connect(self):
        if self.secure:
            return
        nodes, server_info = self.prepare_network()
        entry, hops, _ = select_relay_chain(
            nodes,
            server_info,
            num_nodes=self.num_nodes,
            min_nodes=self.min_nodes,
            use_all=self.use_all,
        )
        self._server_info = server_info
        self._chain = [entry] + hops
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.connect((entry["host"], entry["port"]))
        tcp_enhancer.set_nodelay(self._sock)
        self._onion_sent = False
        self._active = True
        self._insecure_queue = queue.Queue()
        self._recv_thread = threading.Thread(target=self._recv_loop, daemon=True)
        self._recv_thread.start()

    def close(self):
        if self._closed:
            return
        self._closed = True
        try:
            if self.secure:
                self._send_secure(CLIENT_CLOSE)
            elif self._sock is not None and self._active:
                self.coms.send(self._sock, CLIENT_CLOSE)
        except Exception:
            pass
        self._active = False
        if self._sock is not None:
            try:
                self._sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            self._sock.close()
            self._sock = None

    def send(self, data: bytes) -> list[bytes]:
        if self.secure:
            self._secure_replies = self._send_secure(data)
            return self.receive_all()
        if self._sock is None:
            self.connect()
        dest_host = self.dest_host or self._server_info["host"]
        dest_port = self.dest_port or self._server_info["port"]
        sealed = seal_for_server(
            self._server_info["public_key"],
            self.public_key_pem,
            dest_host,
            dest_port,
            data,
        )
        if not self._onion_sent:
            self.coms.send(self._sock, CLIENT_ONION)
            self.coms.send(
                self._sock, build_onion(self._chain, self._server_info, sealed)
            )
            self._onion_sent = True
        else:
            self.coms.send(self._sock, sealed)
        return []

    def receive(self, timeout=None) -> bytes | None:
        if self.secure:
            if not self._secure_replies:
                return None
            return self._secure_replies.pop(0)
        try:
            return self._insecure_queue.get(timeout=timeout)
        except queue.Empty:
            return None

    def receive_all(self) -> list[bytes]:
        if self.secure:
            messages = list(self._secure_replies)
            self._secure_replies.clear()
            return messages
        messages = []
        while True:
            try:
                messages.append(self._insecure_queue.get_nowait())
            except queue.Empty:
                break
        return messages

    def _decrypt_reply(self, sealed, secure=False):
        if sealed is None:
            return None
        if len(sealed) < 256:
            return sealed
        try:
            if secure:
                return open_padded_client_reply(self.private_key, sealed)
            return open_client_reply(self.private_key, sealed)
        except Exception:
            return sealed

    def _send_secure(self, data: bytes) -> list[bytes]:
        nodes, exit_info = self.prepare_network()
        chain, entry, _, _ = select_random_relay_chain(
            nodes,
            exit_info,
            num_nodes=self.num_nodes,
            min_nodes=self.min_nodes,
            use_all=self.use_all,
        )
        full_chain = chain

        dest_host = self.dest_host or exit_info["host"]
        dest_port = self.dest_port or exit_info["port"]

        if data != CLIENT_CLOSE:
            path = [n["port"] for n in full_chain] + [exit_info["port"]]
            print(
                f"  circuit: {' -> '.join(map(str, path))} "
                f"(exit) -> {dest_host}:{dest_port} (server)"
            )

        sealed = seal_padded_for_server(
            exit_info["public_key"], self.public_key_pem, dest_host, dest_port, data
        )
        onion_blob = build_onion(full_chain, exit_info, sealed)

        timing = self._timing() and data != CLIENT_CLOSE
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(CONNECT_TIMEOUT)
            tc0 = time.perf_counter()
            sock.connect((entry["host"], entry["port"]))
            tc1 = time.perf_counter()
            tcp_enhancer.set_nodelay(sock)
            sock.settimeout(RECV_TIMEOUT)
            self.coms.send(sock, CLIENT_ONION)
            self.coms.send(sock, onion_blob)
            ts = time.perf_counter()
            reply_sealed = self.coms.recv(sock)
            tr = time.perf_counter()
        if timing:
            print(
                f"[timing] entry connect {(tc1 - tc0) * 1000:.0f}ms, "
                f"circuit+reply {(tr - ts) * 1000:.0f}ms "
                f"(entry {entry['host']}:{entry['port']}, {len(full_chain)} hops)"
            )

        body = self._decrypt_reply(reply_sealed, secure=True)
        return unpack_server_replies(body)

    def _recv_loop(self):
        while self._active:
            sealed = self.coms.recv(self._sock)
            if sealed is None:
                self._active = False
                break
            msg = self._decrypt_reply(sealed, secure=False)
            if msg is not None:
                self._insecure_queue.put(msg)

    def open_stream(
        self, dest_host: str, dest_port: int, *, verbose=False
    ) -> StreamCircuit:
        """Open a streaming circuit to dest_host:dest_port through the onion network."""
        nodes, exit_info = self.prepare_network()
        chain, entry, _, _ = select_random_relay_chain(
            nodes,
            exit_info,
            num_nodes=self.num_nodes,
            min_nodes=self.min_nodes,
            use_all=self.use_all,
        )
        if verbose:
            path = [n["port"] for n in chain] + [exit_info["port"]]
            print(
                f"  stream circuit: {' -> '.join(map(str, path))} "
                f"(exit) -> {dest_host}:{dest_port}"
            )

        c2e_key = aes.generate_key()
        e2c_key = aes.generate_key()
        sealed = seal_for_server(
            exit_info["public_key"],
            self.public_key_pem,
            dest_host,
            dest_port,
            pack_stream_keys(c2e_key, e2c_key),
        )
        onion_blob = build_onion(chain, exit_info, sealed)

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(CONNECT_TIMEOUT)
        sock.connect((entry["host"], entry["port"]))
        tcp_enhancer.set_nodelay(sock)
        sock.settimeout(None)
        self.coms.send(sock, CLIENT_STREAM)
        self.coms.send(sock, onion_blob)

        return StreamCircuit(
            sock, self.coms, exit_info["public_key"], self.private_key, c2e_key, e2c_key
        )

    def open_tunnel(self, *, verbose=False) -> StreamCircuit:
        """Open a multiplexed tunnel (no destination until streams are opened)."""
        return self.open_stream(TUNNEL_DEST, TUNNEL_PORT, verbose=verbose)

