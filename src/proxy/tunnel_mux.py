import queue
import socket
import threading
import time

from src.client.scattered import Scattered, StreamCircuit
from src.core import tcp_enhancer
from src.core.tunnel_mux import (
    MUX_CLOSE,
    MUX_DATA,
    MUX_OPEN,
    MUX_READY,
    pack_mux_close,
    pack_mux_data,
    pack_mux_open,
    pack_mux_ready,
    parse_mux_frame,
)

CHUNK = 65536


class SharedTunnel:
    """One onion circuit shared across many browser connections."""

    def __init__(self, scattered: Scattered, *, verbose=False):
        self._scattered = scattered
        self._verbose = verbose
        self._circuit: StreamCircuit | None = None
        self._lock = threading.Lock()
        self._next_id = 1
        self._streams: dict[int, queue.Queue] = {}
        self._ready_events: dict[int, threading.Event] = {}
        self._ready = threading.Event()

    def start(self):
        thread = threading.Thread(target=self._run, daemon=True)
        thread.start()
        if not self._ready.wait(timeout=60):
            raise RuntimeError("shared onion tunnel failed to start")

    def _run(self):
        while True:
            if self._verbose:
                print("[proxy] opening shared onion tunnel...")
            self._circuit = self._scattered.open_tunnel(verbose=self._verbose)
            self._ready.set()
            while self._circuit.active:
                data = self._circuit.recv(timeout=1.0)
                if data is None:
                    continue
                parsed = parse_mux_frame(data)
                if not parsed:
                    continue
                cmd, stream_id, _, _, payload = parsed
                if cmd == MUX_READY:
                    event = self._ready_events.get(stream_id)
                    if event is not None:
                        event.set()
                elif cmd == MUX_DATA:
                    q = self._streams.get(stream_id)
                    if q is not None:
                        q.put(payload)
            if self._verbose:
                print("[proxy] shared tunnel circuit closed, reopening...")
            with self._lock:
                self._circuit = None

    def _send(self, payload: bytes):
        with self._lock:
            if not self._circuit or not self._circuit.active:
                raise OSError("shared tunnel closed")
            self._circuit.send(payload)

    def _ensure_circuit(self, timeout=60.0):
        deadline = time.monotonic() + timeout
        while True:
            with self._lock:
                if self._circuit and self._circuit.active:
                    return
            if time.monotonic() >= deadline:
                raise OSError("shared tunnel unavailable")
            time.sleep(0.1)

    def open_stream(self, host: str, port: int, timeout=30.0):
        self._ensure_circuit()
        with self._lock:
            stream_id = self._next_id
            self._next_id += 1
            self._streams[stream_id] = queue.Queue()
            ready = threading.Event()
            self._ready_events[stream_id] = ready
        self._send(pack_mux_open(stream_id, host, port))
        if not ready.wait(timeout=timeout):
            self._streams.pop(stream_id, None)
            self._ready_events.pop(stream_id, None)
            raise TimeoutError(f"stream to {host}:{port} timed out")
        return stream_id

    def send(self, stream_id: int, data: bytes):
        if not data:
            return
        self._send(pack_mux_data(stream_id, data))

    def close_stream(self, stream_id: int):
        try:
            self._send(pack_mux_close(stream_id))
        except OSError:
            pass
        self._streams.pop(stream_id, None)
        self._ready_events.pop(stream_id, None)

    def recv(self, stream_id: int, timeout=1.0) -> bytes | None:
        q = self._streams.get(stream_id)
        if q is None:
            return None
        try:
            return q.get(timeout=timeout)
        except queue.Empty:
            return None


def relay_over_tunnel(tunnel: SharedTunnel, browser_sock: socket.socket, stream_id: int, initial=b""):
    stop = threading.Event()
    tcp_enhancer.set_nodelay(browser_sock)

    def browser_to_tunnel():
        if initial:
            try:
                tunnel.send(stream_id, initial)
            except OSError:
                stop.set()
                return
        while not stop.is_set():
            try:
                data = browser_sock.recv(CHUNK)
            except OSError:
                break
            if not data:
                break
            try:
                tunnel.send(stream_id, data)
            except OSError:
                break
        stop.set()

    def tunnel_to_browser():
        while not stop.is_set():
            data = tunnel.recv(stream_id, timeout=1.0)
            if data is None:
                continue
            try:
                browser_sock.sendall(data)
            except OSError:
                break
        stop.set()

    t1 = threading.Thread(target=browser_to_tunnel, daemon=True)
    t2 = threading.Thread(target=tunnel_to_browser, daemon=True)
    t1.start()
    t2.start()
    t1.join()
    t2.join()
    stop.set()
    tunnel.close_stream(stream_id)
