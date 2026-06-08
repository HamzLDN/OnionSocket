import socket
import threading
import time

from src.core import tcp_enhancer
from src.node.dashboard import NodeDashboard
from src.node.stats import NodeStats
from src.core.asymmetric import rsa
from src.core.e2e import (
    open_from_server,
    open_padded_from_server,
    seal_for_client,
    seal_padded_for_client,
)
from src.core.onion import RSA_CIPHERTEXT_LEN
from src.core.protocol import (
    CLIENT_CLOSE,
    DEFAULT_BIND_HOST,
    DEFAULT_HOST,
    DEFAULT_REGISTRY_PORT,
    PROBE,
    PROBE_KEY,
    SERVICE_EXIT,
    resolve_advertise_host,
)
from src.core.platform import dashboard_available
from src.core.registry_client import maybe_register
from src.core.secure_transport import pack_server_replies


class ClientDisconnected(ConnectionError):
    pass


class ClientConnection:
    def __init__(self, server, sock, addr, conn_id):
        self.server = server
        self.socket = sock
        self.addr = addr
        self.conn_id = conn_id
        self.stats_id = None
        self.public_key = None
        self.dest = None
        self.session = None
        self.session_is_new = False

    def close(self):
        if self.stats_id is not None:
            self.server.stats.close_connection(self.stats_id)
            self.stats_id = None
        self.socket.close()


class ClientSession:
    def __init__(self, sid: int, client_id: bytes, public_key, addr=None):
        self.sid = sid
        self.client_id = client_id
        self.public_key = public_key
        self.addr = addr
        self.outbox = []
        self.messages = []
        now = time.time()
        self.connected_at = now
        self.last_seen = now

    @property
    def label(self) -> str:
        return f"client-{self.sid}"

    def touch(self):
        self.last_seen = time.time()

    def drain_outbox(self):
        messages = list(self.outbox)
        self.outbox.clear()
        return messages


class ExitServer:
    def __init__(
        self,
        host=DEFAULT_BIND_HOST,
        port=10003,
        verbose=False,
        secure=True,
        echo=False,
        *,
        advertise_host=None,
        registry_host=DEFAULT_HOST,
        registry_port=DEFAULT_REGISTRY_PORT,
        register=False,
        quiet=False,
        is_exit_node=False,
        stats: NodeStats | None = None,
    ):
        self.host = host
        self.advertise_host = resolve_advertise_host(host, advertise_host)
        self.port = port
        self.verbose = verbose
        self.quiet = quiet
        self.is_exit_node = is_exit_node
        self.secure = secure and not echo
        self.echo = echo
        if echo:
            mode = "echo"
        elif secure:
            mode = "secure"
        else:
            mode = "chat"
        role = "exit" if is_exit_node else "app"
        should_register = is_exit_node and register
        self.stats = stats or NodeStats(
            role=role,
            advertise_host=self.advertise_host,
            port=port,
            registry=f"{registry_host}:{registry_port}" if should_register else "",
            mode=mode,
        )
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((host, port))
        self.coms = tcp_enhancer.coms()
        self.private_key, self.public_key = rsa.generate_rsa_keys()
        self.sessions = {}
        self.sessions_lock = threading.Lock()
        self._last_session_id = None
        self._next_sid = 1
        self._next_conn_id = 1
        self._listening = False
        label = "Exit node" if is_exit_node else "Application server"
        if not quiet:
            print(f"{label} {self.advertise_host}:{port}")
        self.stats.event(f"{label} online at {self.advertise_host}:{port}")
        maybe_register(
            enabled=should_register,
            service_type=SERVICE_EXIT,
            host=self.advertise_host,
            port=port,
            public_key_pem=rsa.export_public_key(self.public_key),
            registry_host=registry_host,
            registry_port=registry_port,
        )
        if not quiet:
            if echo:
                print("Echo mode")
            elif self.secure:
                print("Secure mode")
            else:
                print("Chat mode")
        if should_register:
            self.stats.event(f"Registering with directory {registry_host}:{registry_port}")

    def close(self):
        self._listening = False
        self.server_socket.close()

    def listen(self, backlog=5):
        self.server_socket.listen(backlog)
        self._listening = True
        if not self.quiet:
            print(f"Listening on {self.host}:{self.port}")
        self.stats.event(f"Listening on {self.host}:{self.port}")

    def accept(self) -> ClientConnection:
        if not self._listening:
            raise RuntimeError("call listen() before accept()")
        client_socket, addr = self.server_socket.accept()
        tcp_enhancer.set_nodelay(client_socket)
        conn_id = self._next_conn_id
        self._next_conn_id += 1
        stats_id = self.stats.open_connection(addr, "client")
        connection = ClientConnection(self, client_socket, addr, conn_id)
        connection.stats_id = stats_id
        return connection

    def _track_recv(self, conn: ClientConnection):
        data = self.coms.recv(conn.socket)
        if data is not None:
            self.stats.record_in(self.stats.wire_len(data), conn.stats_id)
        return data

    def _track_send(self, conn: ClientConnection, payload: bytes):
        self.coms.send(conn.socket, payload)
        self.stats.record_out(self.stats.wire_len(payload), conn.stats_id)

    def receive(self, conn: ClientConnection) -> bytes | None:
        while True:
            data = self._track_recv(conn)
            if data is None:
                return None
            if data == PROBE:
                if self.is_exit_node:
                    self._track_send(conn, f"EXIT:{self.port}".encode())
                    self.stats.note_probe()
                    self.stats.event(f"Probe from {conn.addr[0]}:{conn.addr[1]}")
                    continue
                conn.close()
                return None
            if data == PROBE_KEY:
                self._track_send(conn, rsa.export_public_key(self.public_key))
                self.stats.event(f"Key request from {conn.addr[0]}:{conn.addr[1]}")
                continue

            if self.secure:
                message, public_key, dest = self.parse_incoming_secure(data)
            else:
                message, public_key, dest = self.parse_incoming(data)

            if public_key is not None:
                conn.public_key = public_key
                conn.dest = dest
                conn.session, conn.session_is_new = self._get_or_create_session(
                    public_key, conn.addr
                )

            if message == CLIENT_CLOSE:
                label = conn.session.label if conn.session else "client"
                self._drop_session(conn)
                self._sync_sessions()
                self.stats.event(f"{label} disconnected")
                raise ClientDisconnected(
                    f"client disconnected from {conn.addr[0]}:{conn.addr[1]}"
                )

            if conn.session is not None:
                conn.session.messages.append(message)
            self.stats.note_message()
            if conn.session_is_new and conn.session is not None:
                self.stats.event(f"New session {conn.session.label}")
            preview = message.decode("utf-8", errors="replace")
            if len(preview) > 48:
                preview = preview[:45] + "..."
            self.stats.event(f"Message from {conn.addr[0]}:{conn.addr[1]}: {preview}")
            self._sync_sessions()

            if self.echo:
                self.send(conn, message)
                continue

            return message

    def send(self, conn: ClientConnection, data=None):
        if conn.public_key is None:
            raise ConnectionError("no client public key on connection")

        replies = []
        if conn.session is not None:
            replies.extend(conn.session.drain_outbox())
        if data is not None:
            if isinstance(data, (bytes, bytearray)):
                replies.append(bytes(data))
            else:
                replies.extend(data)

        if not replies:
            return

        if self.secure:
            body = pack_server_replies(replies)
        else:
            body = replies[0]

        if self.verbose:
            print(f"[server {self.port}] send {len(body)} bytes")
        self.send_to_client(conn, conn.public_key, body)

    def _sync_sessions(self):
        self.stats.set_sessions_active(len(self.list_sessions()))

    def get_session(
        self, *, sid=None, public_key=None, client_id=None
    ) -> ClientSession | None:
        if public_key is not None:
            client_id = rsa.export_public_key(public_key)
        with self.sessions_lock:
            if sid is not None:
                for session in self.sessions.values():
                    if session.sid == sid:
                        return session
                return None
            if client_id is None:
                return None
            return self.sessions.get(client_id)

    def list_sessions(self) -> list[ClientSession]:
        with self.sessions_lock:
            return sorted(self.sessions.values(), key=lambda item: item.sid)

    def format_sessions(self) -> str:
        sessions = self.list_sessions()
        if not sessions:
            return "Active sessions: none"
        lines = ["Active sessions:"]
        for session in sessions:
            addr = (
                f"{session.addr[0]}:{session.addr[1]}"
                if session.addr
                else "unknown"
            )
            lines.append(
                f"  {session.label} ({addr}, {len(session.messages)} messages)"
            )
        return "\n".join(lines)

    def active_session(self) -> ClientSession | None:
        with self.sessions_lock:
            if not self.sessions:
                return None
            if self._last_session_id in self.sessions:
                return self.sessions[self._last_session_id]
            return next(iter(self.sessions.values()))

    def queue(self, text: str, *, session=None, sid=None, public_key=None, client_id=None):
        if session is not None:
            session.outbox.append(text.encode("utf-8"))
            return
        target = self.get_session(
            sid=sid, public_key=public_key, client_id=client_id
        )
        if target is None:
            raise KeyError("no session for this client")
        target.outbox.append(text.encode("utf-8"))

    def parse_incoming(self, data):
        if len(data) >= RSA_CIPHERTEXT_LEN:
            try:
                client_pem, dest_host, dest_port, message = open_from_server(
                    self.private_key, data
                )
                if client_pem is not None:
                    dest = (dest_host, dest_port) if dest_host else None
                    return message, rsa.load_public_key(client_pem), dest
            except Exception:
                pass
        return data, None, None

    def parse_incoming_secure(self, data):
        if len(data) >= RSA_CIPHERTEXT_LEN:
            try:
                client_pem, dest_host, dest_port, message = open_padded_from_server(
                    self.private_key, data
                )
                if client_pem is not None:
                    dest = (dest_host, dest_port) if dest_host else None
                    return message, rsa.load_public_key(client_pem), dest
            except Exception:
                pass
        return data, None, None

    def _drop_session(self, conn: ClientConnection):
        if conn.session is None:
            return
        with self.sessions_lock:
            self.sessions.pop(conn.session.client_id, None)
            if self._last_session_id == conn.session.client_id:
                self._last_session_id = None
        conn.session = None

    def _get_or_create_session(self, client_public_key, addr=None):
        if client_public_key is None:
            return None, False
        client_id = rsa.export_public_key(client_public_key)
        with self.sessions_lock:
            session = self.sessions.get(client_id)
            created = session is None
            if created:
                session = ClientSession(self._next_sid, client_id, client_public_key, addr)
                self._next_sid += 1
                self.sessions[client_id] = session
            else:
                session.touch()
                if addr is not None:
                    session.addr = addr
            self._last_session_id = client_id
        return session, created

    def send_to_client(self, conn: ClientConnection, client_public_key, plaintext):
        if client_public_key is None:
            return
        if self.secure:
            sealed = seal_padded_for_client(client_public_key, plaintext)
        else:
            sealed = seal_for_client(client_public_key, plaintext)
        self._track_send(conn, sealed)

    def serve_forever(self, stop_event: threading.Event | None = None, *, echo_handler=None):
        if not self._listening:
            self.listen()
        self.server_socket.settimeout(1.0)
        while stop_event is None or not stop_event.is_set():
            try:
                conn = self.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                message = self.receive(conn)
                if message is None:
                    continue
                if echo_handler is not None:
                    echo_handler(conn, message)
                elif self.echo:
                    self.send(conn, message)
            except ClientDisconnected as e:
                self.stats.event(str(e))
            finally:
                conn.close()

    def run_with_dashboard(self, *, echo_handler=None):
        if not dashboard_available():
            if not self.quiet:
                print("Dashboard unavailable on this platform, using plain mode.")
            self.serve_forever(echo_handler=echo_handler)
            return
        stop_event = threading.Event()
        threading.Thread(
            target=self.serve_forever,
            args=(stop_event,),
            kwargs={"echo_handler": echo_handler},
            daemon=True,
        ).start()
        NodeDashboard(self.stats, stop_event).run()
        stop_event.set()
        self.close()
        if not self.quiet:
            print("Exit node stopped.")
