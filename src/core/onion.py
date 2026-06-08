import struct

from src.core.asymmetric import rsa
from src.core.symmetric import aes

RSA_CIPHERTEXT_LEN = 256
HOP_NODE = b"N"
HOP_SERVER = b"S"


def pack_hop(hop_type, host, port, inner):
    host_bytes = host.encode("utf-8")
    return (
        hop_type
        + struct.pack(">H", len(host_bytes))
        + host_bytes
        + struct.pack(">I", port)
        + struct.pack(">I", len(inner))
        + inner
    )


def parse_hop(data):
    hop_type = data[:1]
    host_len = struct.unpack(">H", data[1:3])[0]
    offset = 3
    host = data[offset : offset + host_len].decode("utf-8")
    offset += host_len
    port = struct.unpack(">I", data[offset : offset + 4])[0]
    offset += 4
    inner_len = struct.unpack(">I", data[offset : offset + 4])[0]
    offset += 4
    inner = data[offset : offset + inner_len]
    return hop_type, host, port, inner


def wrap_layer(public_key, plaintext):
    session_key = aes.generate_key()
    encrypted_body = aes.encrypt(plaintext, session_key)
    encrypted_key = rsa.encrypt_message(public_key, session_key)
    return encrypted_key + encrypted_body


def unwrap_layer(private_key, layer_blob):
    encrypted_key = layer_blob[:RSA_CIPHERTEXT_LEN]
    encrypted_body = layer_blob[RSA_CIPHERTEXT_LEN:]
    session_key = rsa.decrypt_message(private_key, encrypted_key)
    return aes.decrypt(encrypted_body, session_key)


def build_onion(chain, server, payload=b""):
    inner = pack_hop(HOP_SERVER, server["host"], server["port"], payload)
    inner = wrap_layer(chain[-1]["public_key"], inner)

    for i in range(len(chain) - 2, -1, -1):
        next_node = chain[i + 1]
        body = pack_hop(HOP_NODE, next_node["host"], next_node["port"], inner)
        inner = wrap_layer(chain[i]["public_key"], body)

    return inner


def peel_layer(private_key, layer_blob):
    plaintext = unwrap_layer(private_key, layer_blob)
    hop_type, host, port, inner = parse_hop(plaintext)
    return hop_type, host, port, inner


def format_peel_report(node_port, hop_type, host, port, inner):
    if hop_type == HOP_SERVER:
        layer_place = "last relay (peels to exit server)"
        forward_label = "exit server"
        forward_target = f"{host}:{port}"
    else:
        layer_place = "relay hop (peels to next node)"
        forward_label = "next relay node"
        forward_target = f"{host}:{port}"

    lines = [
        f"\n[node {node_port}] decrypted onion layer at: {layer_place}",
        f"  this relay:     localhost:{node_port}",
        f"  forward to:     {forward_label} @ {forward_target}",
        f"  hop type:       {hop_type.decode()} ({'server' if hop_type == HOP_SERVER else 'node'})",
        f"  inner size:     {len(inner)} bytes",
    ]

    if hop_type == HOP_SERVER:
        if not inner:
            lines.append(
                "  decrypted data: (empty — circuit setup only; "
                "chat messages use the open tunnel next)"
            )
        elif len(inner) >= 256:
            lines.append(
                "  decrypted data: E2E ciphertext for exit server only "
                f"({len(inner)} bytes — this relay cannot read the message)"
            )
            preview = inner[:32].hex()
            lines.append(f"  ciphertext preview: {preview}...")
        else:
            try:
                lines.append(f"  decrypted data: {inner.decode('utf-8')!r}")
            except UnicodeDecodeError:
                lines.append(f"  decrypted data: {inner!r}")
    elif inner:
        preview = inner[:32].hex()
        suffix = "..." if len(inner) > 32 else ""
        lines.append(
            f"  decrypted data: {len(inner)} bytes ciphertext for next hop "
            f"(preview: {preview}{suffix})"
        )
    else:
        lines.append("  decrypted data: (empty)")

    return "\n".join(lines)

