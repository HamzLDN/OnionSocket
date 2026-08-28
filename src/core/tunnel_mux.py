import struct

TUNNEL_DEST = "__onion_tunnel__"
TUNNEL_PORT = 0

MUX_OPEN = 1
MUX_DATA = 2
MUX_CLOSE = 3
MUX_READY = 4


def pack_mux_ready(stream_id: int) -> bytes:
    return bytes([MUX_READY]) + struct.pack(">I", stream_id)


def pack_mux_open(stream_id: int, host: str, port: int) -> bytes:
    host_b = host.encode("utf-8")
    return (
        bytes([MUX_OPEN])
        + struct.pack(">IH", stream_id, len(host_b))
        + host_b
        + struct.pack(">I", int(port))
    )


def pack_mux_data(stream_id: int, payload: bytes) -> bytes:
    return bytes([MUX_DATA]) + struct.pack(">I", stream_id) + payload


def pack_mux_close(stream_id: int) -> bytes:
    return bytes([MUX_CLOSE]) + struct.pack(">I", stream_id)


def parse_mux_frame(data: bytes):
    if not data:
        return None
    cmd = data[0]
    if cmd == MUX_OPEN:
        stream_id, host_len = struct.unpack(">IH", data[1:7])
        host = data[7 : 7 + host_len].decode("utf-8")
        port = struct.unpack(">I", data[7 + host_len : 7 + host_len + 4])[0]
        return MUX_OPEN, stream_id, host, port, b""
    if cmd == MUX_DATA:
        stream_id = struct.unpack(">I", data[1:5])[0]
        return MUX_DATA, stream_id, None, None, data[5:]
    if cmd == MUX_CLOSE:
        stream_id = struct.unpack(">I", data[1:5])[0]
        return MUX_CLOSE, stream_id, None, None, b""
    if cmd == MUX_READY:
        stream_id = struct.unpack(">I", data[1:5])[0]
        return MUX_READY, stream_id, None, None, b""
    return None
