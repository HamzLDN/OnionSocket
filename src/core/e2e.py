import struct

from src.core.asymmetric import rsa
from src.core.onion import unwrap_layer, wrap_layer


def pack_client_to_server(client_public_pem: bytes, message: bytes) -> bytes:
    return struct.pack(">I", len(client_public_pem)) + client_public_pem + message


def unpack_client_to_server(data: bytes):
    if len(data) < 4:
        return None, data
    pem_len = struct.unpack(">I", data[:4])[0]
    if pem_len <= 0 or pem_len > len(data) - 4:
        return None, data
    pem = data[4 : 4 + pem_len]
    if not pem.startswith(b"-----BEGIN"):
        return None, data
    message = data[4 + pem_len :]
    return pem, message


def seal_for_peer(public_key, plaintext: bytes) -> bytes:
    return wrap_layer(public_key, plaintext)


def open_from_peer(private_key, sealed: bytes) -> bytes:
    return unwrap_layer(private_key, sealed)


def seal_for_server(server_public_key, client_public_pem: bytes, message: bytes) -> bytes:
    inner = pack_client_to_server(client_public_pem, message)
    return seal_for_peer(server_public_key, inner)


def seal_padded_for_server(server_public_key, client_public_pem: bytes, message: bytes) -> bytes:
    from src.core.secure_transport import pad_payload

    return seal_for_server(server_public_key, client_public_pem, pad_payload(message))


def open_from_server(server_private_key, sealed: bytes):
    inner = open_from_peer(server_private_key, sealed)
    return unpack_client_to_server(inner)


def open_padded_from_server(server_private_key, sealed: bytes):
    from src.core.secure_transport import unpad_payload

    pem, padded = open_from_server(server_private_key, sealed)
    if pem is None:
        return None, unpad_payload(padded)
    return pem, unpad_payload(padded)


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
