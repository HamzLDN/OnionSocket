import struct

from src.core.asymmetric import rsa
from src.core.onion import unwrap_layer, wrap_layer


def pack_client_to_server(
    client_public_pem: bytes, dest_host: str, dest_port: int, message: bytes
) -> bytes:
    host_bytes = dest_host.encode("utf-8")
    return (
        struct.pack(">I", len(client_public_pem))
        + client_public_pem
        + struct.pack(">H", len(host_bytes))
        + host_bytes
        + struct.pack(">I", int(dest_port))
        + message
    )


def unpack_client_to_server(data: bytes):
    if len(data) < 4:
        return None, None, None, data
    pem_len = struct.unpack(">I", data[:4])[0]
    if pem_len <= 0 or pem_len > len(data) - 4:
        return None, None, None, data
    pem = data[4 : 4 + pem_len]
    if not pem.startswith(b"-----BEGIN"):
        return None, None, None, data
    offset = 4 + pem_len
    if offset + 2 > len(data):
        return None, None, None, data
    host_len = struct.unpack(">H", data[offset : offset + 2])[0]
    offset += 2
    if offset + host_len + 4 > len(data):
        return None, None, None, data
    dest_host = data[offset : offset + host_len].decode("utf-8")
    offset += host_len
    dest_port = struct.unpack(">I", data[offset : offset + 4])[0]
    offset += 4
    message = data[offset:]
    return pem, dest_host, dest_port, message


def seal_for_peer(public_key, plaintext: bytes) -> bytes:
    return wrap_layer(public_key, plaintext)


def open_from_peer(private_key, sealed: bytes) -> bytes:
    return unwrap_layer(private_key, sealed)


def seal_for_server(
    server_public_key,
    client_public_pem: bytes,
    dest_host: str,
    dest_port: int,
    message: bytes,
) -> bytes:
    inner = pack_client_to_server(client_public_pem, dest_host, dest_port, message)
    return seal_for_peer(server_public_key, inner)


def seal_padded_for_server(
    server_public_key,
    client_public_pem: bytes,
    dest_host: str,
    dest_port: int,
    message: bytes,
) -> bytes:
    from src.core.secure_transport import pad_payload

    return seal_for_server(
        server_public_key, client_public_pem, dest_host, dest_port, pad_payload(message)
    )


def open_from_server(server_private_key, sealed: bytes):
    inner = open_from_peer(server_private_key, sealed)
    return unpack_client_to_server(inner)


def open_padded_from_server(server_private_key, sealed: bytes):
    from src.core.secure_transport import unpad_payload

    pem, dest_host, dest_port, padded = open_from_server(server_private_key, sealed)
    if pem is None:
        return None, None, None, unpad_payload(padded)
    return pem, dest_host, dest_port, unpad_payload(padded)


def seal_for_client(client_public_key, message: bytes) -> bytes:
    return seal_for_peer(client_public_key, message)


def seal_padded_for_client(client_public_key, message: bytes) -> bytes:
    from src.core.secure_transport import pad_payload

    return seal_for_client(client_public_key, pad_payload(message))


def open_client_reply(client_private_key, sealed: bytes) -> bytes:
    return open_from_peer(client_private_key, sealed)


def open_padded_client_reply(client_private_key, sealed: bytes) -> bytes:
    from src.core.secure_transport import unpad_payload

    return unpad_payload(open_client_reply(client_private_key, sealed))


STREAM_FRAME = b"\x01"
STREAM_KEY_BYTES = 32


def pack_stream_keys(c2e_key: bytes, e2c_key: bytes) -> bytes:
    return c2e_key + e2c_key


def parse_stream_keys(message: bytes) -> tuple[bytes | None, bytes | None]:
    if len(message) != STREAM_KEY_BYTES:
        return None, None
    return message[:16], message[16:]


def seal_stream(key: bytes, data: bytes) -> bytes:
    from src.core.symmetric import aes

    return STREAM_FRAME + aes.encrypt(data, key)


def open_stream_data(key: bytes, framed: bytes) -> bytes:
    from src.core.symmetric import aes

    if not framed.startswith(STREAM_FRAME):
        raise ValueError("not a stream frame")
    return aes.decrypt(framed[len(STREAM_FRAME) :], key)


def is_stream_frame(data: bytes) -> bool:
    return data.startswith(STREAM_FRAME)
