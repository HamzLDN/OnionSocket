import os
import struct

PADDED_BLOCK = 512


def pad_payload(data: bytes, block_size=PADDED_BLOCK) -> bytes:
    if len(data) > block_size - 4:
        raise ValueError(f"payload too large for {block_size}-byte block")
    inner = struct.pack(">I", len(data)) + data
    return inner + os.urandom(block_size - len(inner))


def unpad_payload(padded: bytes) -> bytes:
    if len(padded) < 4:
        return padded
    length = struct.unpack(">I", padded[:4])[0]
    if length > len(padded) - 4:
        return padded[4:]
    return padded[4 : 4 + length]


def pack_server_replies(messages):
    if not messages:
        return b""
    parts = [struct.pack(">I", len(m)) + m for m in messages]
    return struct.pack(">I", len(messages)) + b"".join(parts)


def unpack_server_replies(data):
    if not data or len(data) < 4:
        return []
    count = struct.unpack(">I", data[:4])[0]
    offset = 4
    messages = []
    for _ in range(count):
        if offset + 4 > len(data):
            break
        length = struct.unpack(">I", data[offset : offset + 4])[0]
        offset += 4
        messages.append(data[offset : offset + length])
        offset += length
    return messages


