import sys
import threading
import time
from collections import deque
from dataclasses import dataclass, field

try:
    import resource
except ImportError:
    resource = None


def _memory_mb() -> float:
    if resource is None:
        return 0.0
    rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    if sys.platform == "darwin":
        return rss / (1024 * 1024)
    if sys.platform == "win32":
        return rss / (1024 * 1024)
    return rss / 1024


def _cpu_seconds() -> float:
    if resource is None:
        return 0.0
    usage = resource.getrusage(resource.RUSAGE_SELF)
    return usage.ru_utime + usage.ru_stime


def format_bytes(n: float) -> str:
    n = float(n)
    if n < 1024:
        return f"{n:.0f} B"
    if n < 1024 * 1024:
        return f"{n / 1024:.1f} KB"
    if n < 1024 * 1024 * 1024:
        return f"{n / (1024 * 1024):.2f} MB"
    return f"{n / (1024 * 1024 * 1024):.2f} GB"


def format_rate(n: float) -> str:
    return f"{format_bytes(n)}/s"


@dataclass
class ConnectionRecord:
    conn_id: int
    addr: str
    kind: str
    opened_at: float = field(default_factory=time.monotonic)
    bytes_in: int = 0
    bytes_out: int = 0
    closed: bool = False


class NodeStats:
    def __init__(
        self,
        *,
        role: str,
        advertise_host: str,
        port: int,
        registry: str = "",
        mode: str = "",
    ):
        self.role = role
        self.advertise_host = advertise_host
        self.port = port
        self.registry = registry
        self.mode = mode
        self.started_at = time.monotonic()
        self.lock = threading.Lock()

        self.bytes_in = 0
        self.bytes_out = 0
        self.total_connections = 0
        self.active_connections = 0
        self.circuits_forwarded = 0
        self.onion_entries = 0
        self.relay_hops = 0
        self.probes = 0
        self.messages = 0
        self.sessions_active = 0

        self.current_in_rate = 0.0
        self.current_out_rate = 0.0
        self.peak_in_rate = 0.0
        self.peak_out_rate = 0.0
        self.rate_history: deque[tuple[float, float, float]] = deque(maxlen=60)

        self._last_sample_in = 0
        self._last_sample_out = 0
        self._next_conn_id = 1
        self._live: dict[int, ConnectionRecord] = {}
        self.connections: deque[ConnectionRecord] = deque(maxlen=80)
        self.events: deque[str] = deque(maxlen=120)

    def uptime(self) -> float:
        return time.monotonic() - self.started_at

    def format_uptime(self) -> str:
        seconds = int(self.uptime())
        hours, rem = divmod(seconds, 3600)
        minutes, secs = divmod(rem, 60)
        if hours:
            return f"{hours}h {minutes}m {secs}s"
        if minutes:
            return f"{minutes}m {secs}s"
        return f"{secs}s"

    def event(self, message: str):
        stamp = time.strftime("%H:%M:%S")
        with self.lock:
            self.events.appendleft(f"[{stamp}] {message}")

    def open_connection(self, addr, kind: str) -> int:
        with self.lock:
            conn_id = self._next_conn_id
            self._next_conn_id += 1
            record = ConnectionRecord(
                conn_id=conn_id,
                addr=f"{addr[0]}:{addr[1]}",
                kind=kind,
            )
            self._live[conn_id] = record
            self.connections.appendleft(record)
            self.total_connections += 1
            self.active_connections += 1
        return conn_id

    def close_connection(self, conn_id: int):
        with self.lock:
            record = self._live.pop(conn_id, None)
            if record is not None:
                record.closed = True
            if self.active_connections > 0:
                self.active_connections -= 1

    def record_in(self, nbytes: int, conn_id: int | None = None):
        if nbytes <= 0:
            return
        with self.lock:
            self.bytes_in += nbytes
            if conn_id is not None and conn_id in self._live:
                self._live[conn_id].bytes_in += nbytes

    def record_out(self, nbytes: int, conn_id: int | None = None):
        if nbytes <= 0:
            return
        with self.lock:
            self.bytes_out += nbytes
            if conn_id is not None and conn_id in self._live:
                self._live[conn_id].bytes_out += nbytes

    def wire_len(self, payload: bytes | None) -> int:
        if not payload:
            return 0
        return 4 + len(payload)

    def set_connection_kind(self, conn_id: int, kind: str):
        with self.lock:
            if conn_id in self._live:
                self._live[conn_id].kind = kind

    def note_peel(self):
        with self.lock:
            self.circuits_forwarded += 1

    def note_client_circuit(self):
        with self.lock:
            self.onion_entries += 1

    def note_relay_hop(self):
        with self.lock:
            self.relay_hops += 1

    def note_probe(self):
        with self.lock:
            self.probes += 1

    def note_message(self):
        with self.lock:
            self.messages += 1

    def set_sessions_active(self, count: int):
        with self.lock:
            self.sessions_active = count

    def tick_rates(self):
        with self.lock:
            delta_in = self.bytes_in - self._last_sample_in
            delta_out = self.bytes_out - self._last_sample_out
            self._last_sample_in = self.bytes_in
            self._last_sample_out = self.bytes_out
            self.current_in_rate = float(delta_in)
            self.current_out_rate = float(delta_out)
            self.peak_in_rate = max(self.peak_in_rate, self.current_in_rate)
            self.peak_out_rate = max(self.peak_out_rate, self.current_out_rate)
            self.rate_history.append(
                (time.monotonic(), self.current_in_rate, self.current_out_rate)
            )

    def snapshot(self):
        with self.lock:
            return {
                "role": self.role,
                "advertise_host": self.advertise_host,
                "port": self.port,
                "registry": self.registry,
                "mode": self.mode,
                "uptime": self.format_uptime(),
                "bytes_in": self.bytes_in,
                "bytes_out": self.bytes_out,
                "total_connections": self.total_connections,
                "active_connections": self.active_connections,
                "circuits_forwarded": self.circuits_forwarded,
                "onion_entries": self.onion_entries,
                "relay_hops": self.relay_hops,
                "probes": self.probes,
                "messages": self.messages,
                "sessions_active": self.sessions_active,
                "current_in_rate": self.current_in_rate,
                "current_out_rate": self.current_out_rate,
                "peak_in_rate": self.peak_in_rate,
                "peak_out_rate": self.peak_out_rate,
                "rate_history": list(self.rate_history),
                "connections": list(self.connections),
                "events": list(self.events),
                "threads": threading.active_count(),
                "memory_mb": _memory_mb(),
                "cpu_seconds": _cpu_seconds(),
            }
