import queue
import socket
import threading

from src.core import tcp_enhancer
from src.core.asymmetric import rsa
from src.core.discovery import (
    dedupe_nodes_by_port,
    discover_network,
    enrich_chain_with_pubkeys,
    enrich_server_with_pubkey,
    resolve_live_exit,
    select_random_relay_chain,
    select_relay_chain,
)
from src.core.e2e import (
    open_client_reply,
    open_padded_client_reply,
    seal_for_server,
    seal_padded_for_server,
)
from src.core.onion import build_onion
from src.core.protocol import (
    CLIENT_CLOSE,
    CLIENT_ONION,
    DEFAULT_HOST,
    DEFAULT_REGISTRY_PORT,
    DEFAULT_SCAN_END,
    DEFAULT_SCAN_START,
    MIN_RELAY_NODES,
)
from src.core.secure_transport import unpack_server_replies


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
        server_host=None,
        server_port=None,
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
        self.server_host = server_host
        self.server_port = server_port
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
        nodes, server = discover_network(
            registry_host=self.registry_host,
            registry_port=self.registry_port,
            use_registry=self.use_registry,
            scan_host=self.scan_host,
            scan_start=self.scan_start,
            scan_end=self.scan_end,
            exit_port=self.server_port,
        )
        if self.server_host is not None and self.server_port is not None:
            explicit = {"host": self.server_host, "port": self.server_port}
            if server and int(server.get("port", -1)) == self.server_port:
                if server.get("public_key_pem"):
                    explicit["public_key_pem"] = server["public_key_pem"]
            live = resolve_live_exit(
                explicit, prefer_host=self.server_host or self.scan_host
            )
            if live is None and server is not None:
                live = server
            if live is None:
                raise RuntimeError(
                    f"exit node not reachable at {self.server_host}:{self.server_port} "
                    f"(is exit.py running on that port?)"
                )
            server = live
        elif server is None:
            raise RuntimeError(
                "no exit node found on the network (start exit.py first)"
            )
        prefer = server["host"]
        nodes = dedupe_nodes_by_port(nodes, prefer)
        return nodes, server

    def prepare_network(self):
        if self._nodes_cache is not None and self._server_info is not None:
            return self._nodes_cache, self._server_info
        nodes, server = self.load_network()
        self._nodes_cache = enrich_chain_with_pubkeys(nodes)
        self._server_info = enrich_server_with_pubkey(server)
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
        sealed = seal_for_server(
            self._server_info["public_key"], self.public_key_pem, data
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
        nodes, server_info = self.prepare_network()
        chain, entry, _, _ = select_random_relay_chain(
            nodes,
            server_info,
            num_nodes=self.num_nodes,
            min_nodes=self.min_nodes,
            use_all=self.use_all,
        )
        full_chain = chain

        if data != CLIENT_CLOSE:
            path = [n["port"] for n in full_chain] + [server_info["port"]]
            print(f"  circuit: {' -> '.join(map(str, path))}")

        sealed = seal_padded_for_server(
            server_info["public_key"], self.public_key_pem, data
        )
        onion_blob = build_onion(full_chain, server_info, sealed)

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect((entry["host"], entry["port"]))
            self.coms.send(sock, CLIENT_ONION)
            self.coms.send(sock, onion_blob)
            reply_sealed = self.coms.recv(sock)

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

