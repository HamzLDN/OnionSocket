import socket
import threading

from src.core import tcp_enhancer
from src.core.asymmetric import rsa
from src.core.e2e import (
    is_stream_frame,
    open_from_peer,
    open_from_server,
    open_padded_from_server,
    open_stream_data,
    parse_stream_keys,
    seal_for_client,
    seal_stream,
)
from src.core.onion import RSA_CIPHERTEXT_LEN
from src.core.protocol import CLIENT_CLOSE, CONNECT_TIMEOUT, PROBE, PROBE_KEY
from src.core.tunnel_mux import (
    MUX_CLOSE,
    MUX_DATA,
    MUX_OPEN,
    MUX_READY,
    TUNNEL_DEST,
    pack_mux_data,
    pack_mux_ready,
    parse_mux_frame,
)
from src.server.exit_server import ClientConnection, ClientDisconnected, ExitServer


def _handle_probe(server: ExitServer, conn: ClientConnection, first: bytes) -> bool:
    coms = tcp_enhancer.coms()
    if first == PROBE:
        if server.is_exit_node:
            coms.send(conn.socket, f"EXIT:{server.port}".encode())
            server.stats.note_probe()
        conn.close()
        return True
    if first == PROBE_KEY:
        coms.send(conn.socket, rsa.export_public_key(server.public_key))
        conn.close()
        return True
    return False


def _open_first(server: ExitServer, sealed: bytes):
    if len(sealed) < RSA_CIPHERTEXT_LEN:
        return None, None, None, sealed
    try:
        if server.secure:
            return open_padded_from_server(server.private_key, sealed)
        return open_from_server(server.private_key, sealed)
    except Exception:
        return None, None, None, sealed


def relay_stream(
    server: ExitServer,
    conn: ClientConnection,
    *,
    verbose=False,
    first_sealed: bytes | None = None,
    c2e_key: bytes | None = None,
    e2c_key: bytes | None = None,
):
    """Bidirectional TCP relay: onion tunnel ↔ remote destination."""
    coms = tcp_enhancer.coms()
    sealed = first_sealed if first_sealed is not None else coms.recv(conn.socket)
    if sealed is None:
        return
    if _handle_probe(server, conn, sealed):
        return

    client_pem, dest_host, dest_port, initial = _open_first(server, sealed)
    if client_pem is None or not dest_host:
        return

    if c2e_key is None or e2c_key is None:
        c2e_key, e2c_key = parse_stream_keys(initial)
        if c2e_key is not None:
            initial = b""
    else:
        initial = b""

    client_pubkey = rsa.load_public_key(client_pem)
    if verbose:
        print(f"[exit] stream to {dest_host}:{dest_port}")

    remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        remote.settimeout(CONNECT_TIMEOUT)
        remote.connect((dest_host, int(dest_port)))
        tcp_enhancer.set_nodelay(remote)
        remote.settimeout(None)
    except OSError as e:
        if verbose:
            print(f"[exit] stream destination unreachable: {e}")
        return

    if initial:
        remote.sendall(initial)

    server.stats.event(f"Stream {dest_host}:{dest_port} from {conn.addr[0]}:{conn.addr[1]}")
    stop = threading.Event()

    def decrypt_chunk(chunk: bytes) -> bytes | None:
        if c2e_key is not None and is_stream_frame(chunk):
            return open_stream_data(c2e_key, chunk)
        try:
            return open_from_peer(server.private_key, chunk)
        except Exception:
            return None

    def encrypt_chunk(data: bytes) -> bytes:
        if e2c_key is not None:
            return seal_stream(e2c_key, data)
        return seal_for_client(client_pubkey, data)

    def client_to_remote():
        while not stop.is_set():
            chunk = coms.recv(conn.socket)
            if chunk is None:
                break
            data = decrypt_chunk(chunk)
            if not data:
                continue
            try:
                remote.sendall(data)
            except OSError:
                break
        stop.set()

    def remote_to_client():
        remote.settimeout(1.0)
        while not stop.is_set():
            try:
                data = remote.recv(65536)
            except socket.timeout:
                continue
            except OSError:
                break
            if not data:
                break
            try:
                coms.send(conn.socket, encrypt_chunk(data))
            except OSError:
                break
        stop.set()

    t1 = threading.Thread(target=client_to_remote, daemon=True)
    t2 = threading.Thread(target=remote_to_client, daemon=True)
    t1.start()
    t2.start()
    t1.join()
    t2.join()

    stop.set()
    try:
        remote.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass
    remote.close()


def relay_mux(
    server: ExitServer,
    conn: ClientConnection,
    *,
    verbose=False,
    first_sealed: bytes | None = None,
    c2e_key: bytes | None = None,
    e2c_key: bytes | None = None,
):
    """Multiplex many destinations over one onion connection."""
    coms = tcp_enhancer.coms()
    sealed = first_sealed if first_sealed is not None else coms.recv(conn.socket)
    if sealed is None:
        return
    if _handle_probe(server, conn, sealed):
        return

    client_pem, dest_host, dest_port, initial = _open_first(server, sealed)
    if client_pem is None or dest_host != TUNNEL_DEST:
        return

    if c2e_key is None or e2c_key is None:
        c2e_key, e2c_key = parse_stream_keys(initial)
    if c2e_key is None or e2c_key is None:
        return

    if verbose:
        print("[exit] multiplex tunnel")

    streams: dict[int, socket.socket] = {}
    pending: dict[int, list[bytes]] = {}
    streams_lock = threading.Lock()
    stop = threading.Event()

    def decrypt_chunk(chunk: bytes) -> bytes | None:
        if is_stream_frame(chunk):
            try:
                return open_stream_data(c2e_key, chunk)
            except Exception:
                return None
        return None

    def send_mux(mux_payload: bytes):
        framed = seal_stream(e2c_key, mux_payload)
        coms.send(conn.socket, framed)

    def send_to_client(stream_id: int, payload: bytes):
        send_mux(pack_mux_data(stream_id, payload))

    def close_stream(stream_id: int):
        with streams_lock:
            remote = streams.pop(stream_id, None)
        if remote is not None:
            try:
                remote.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            remote.close()

    def remote_reader(stream_id: int, remote: socket.socket):
        remote.settimeout(1.0)
        while not stop.is_set():
            try:
                data = remote.recv(65536)
            except socket.timeout:
                continue
            except OSError:
                break
            if not data:
                break
            try:
                send_to_client(stream_id, data)
            except OSError:
                break
        close_stream(stream_id)

    def open_remote(stream_id: int, host: str, port: int):
        remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        remote.settimeout(CONNECT_TIMEOUT)
        remote.connect((host, int(port)))
        tcp_enhancer.set_nodelay(remote)
        remote.settimeout(None)
        with streams_lock:
            streams[stream_id] = remote
            queued = pending.pop(stream_id, [])
        for chunk in queued:
            remote.sendall(chunk)
        try:
            send_mux(pack_mux_ready(stream_id))
        except OSError:
            close_stream(stream_id)
            return
        if verbose:
            print(f"[exit] mux stream {stream_id} -> {host}:{port}")
        threading.Thread(
            target=remote_reader, args=(stream_id, remote), daemon=True
        ).start()

    while not stop.is_set():
        chunk = coms.recv(conn.socket)
        if chunk is None:
            break
        data = decrypt_chunk(chunk)
        if not data:
            continue
        parsed = parse_mux_frame(data)
        if not parsed:
            continue
        cmd, stream_id, host, port, payload = parsed
        if cmd == MUX_OPEN:
            def _open():
                try:
                    open_remote(stream_id, host, port)
                except OSError as e:
                    if verbose:
                        print(f"[exit] mux open failed: {e}")
                    close_stream(stream_id)

            threading.Thread(target=_open, daemon=True).start()
        elif cmd == MUX_DATA:
            with streams_lock:
                remote = streams.get(stream_id)
            if remote is None:
                pending.setdefault(stream_id, []).append(payload)
                continue
            try:
                remote.sendall(payload)
            except OSError:
                close_stream(stream_id)
        elif cmd == MUX_CLOSE:
            close_stream(stream_id)

    stop.set()
    with streams_lock:
        ids = list(streams.keys())
    for stream_id in ids:
        close_stream(stream_id)


def serve_connection(
    server: ExitServer,
    conn: ClientConnection,
    *,
    verbose=False,
    echo=False,
    reply_for=None,
):
    """Auto-detect stream (web proxy) vs one-shot message handling."""
    coms = tcp_enhancer.coms()
    first = coms.recv(conn.socket)
    if first is None:
        return
    if _handle_probe(server, conn, first):
        return

    client_pem, dest_host, dest_port, message = _open_first(server, first)
    if client_pem is not None:
        conn.public_key = rsa.load_public_key(client_pem)
        conn.dest = (dest_host, dest_port) if dest_host else None

    c2e_key, e2c_key = parse_stream_keys(message)
    if client_pem and dest_host == TUNNEL_DEST:
        relay_mux(
            server,
            conn,
            verbose=verbose,
            first_sealed=first,
            c2e_key=c2e_key,
            e2c_key=e2c_key,
        )
        return
    if client_pem and dest_host and (message == b"" or c2e_key is not None):
        relay_stream(
            server,
            conn,
            verbose=verbose,
            first_sealed=first,
            c2e_key=c2e_key,
            e2c_key=e2c_key,
        )
        return

    if message == CLIENT_CLOSE:
        raise ClientDisconnected(f"client disconnected from {conn.addr[0]}:{conn.addr[1]}")

    if echo:
        server.send(conn, message)
        return

    if reply_for is not None and message is not None:
        server.send(conn, reply_for(conn, message, echo=echo, verbose=verbose))
