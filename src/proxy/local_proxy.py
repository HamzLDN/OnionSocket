import socket
import threading

from src.client.scattered import Scattered
from src.core import tcp_enhancer
from src.core.protocol import DEFAULT_HOST
from src.proxy.tunnel_mux import SharedTunnel, relay_over_tunnel

CHUNK = 65536


def _read_headers(sock) -> tuple[bytes, bytes]:
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            break
        buf += chunk
    if b"\r\n\r\n" not in buf:
        return buf, b""
    end = buf.index(b"\r\n\r\n") + 4
    return buf[:end], buf[end:]


def _parse_connect_target(headers: bytes) -> tuple[str, int] | None:
    first = headers.split(b"\r\n", 1)[0]
    parts = first.split()
    if len(parts) < 2 or parts[0].upper() != b"CONNECT":
        return None
    host_port = parts[1].decode("ascii", errors="replace")
    if host_port.startswith("[") and "]" in host_port:
        host = host_port[1 : host_port.index("]")]
        port = int(host_port.split("]:", 1)[1])
        return host, port
    if ":" in host_port:
        host, port_s = host_port.rsplit(":", 1)
        return host, int(port_s)
    return host_port, 443


def _parse_http_target(headers: bytes) -> tuple[str, int, bytes] | None:
    first = headers.split(b"\r\n", 1)[0]
    parts = first.split()
    if len(parts) < 2:
        return None
    method = parts[0].upper().decode("ascii", errors="replace")
    url = parts[1].decode("ascii", errors="replace")
    if method not in ("GET", "POST", "HEAD", "PUT", "DELETE", "PATCH", "OPTIONS"):
        return None
    if url.startswith("http://"):
        rest = url[7:]
        if "/" in rest:
            host_port, _path = rest.split("/", 1)
        else:
            host_port = rest
        if ":" in host_port:
            host, port_s = host_port.rsplit(":", 1)
            port = int(port_s)
        else:
            host, port = host_port, 80
        return host, port, headers
    host = None
    for line in headers.split(b"\r\n"):
        if line.lower().startswith(b"host:"):
            host = line.split(b":", 1)[1].strip().decode("ascii", errors="replace")
            break
    if not host:
        return None
    if ":" in host:
        h, port_s = host.rsplit(":", 1)
        return h, int(port_s), headers
    return host, 80, headers


def _handle_connection(browser_sock, tunnel: SharedTunnel, verbose=False):
    try:
        tcp_enhancer.set_nodelay(browser_sock)
        browser_sock.settimeout(120)
        headers, leftover = _read_headers(browser_sock)
        if not headers:
            return

        target = _parse_connect_target(headers)
        if target is not None:
            host, port = target
            if verbose:
                print(f"[proxy] CONNECT {host}:{port}")
            try:
                stream_id = tunnel.open_stream(host, port)
            except (OSError, TimeoutError) as e:
                if verbose:
                    print(f"[proxy] tunnel stream failed: {e}")
                browser_sock.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                return
            browser_sock.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            relay_over_tunnel(tunnel, browser_sock, stream_id, leftover)
            return

        http_target = _parse_http_target(headers)
        if http_target is not None:
            host, port, forward_headers = http_target
            if verbose:
                print(f"[proxy] HTTP {host}:{port}")
            try:
                stream_id = tunnel.open_stream(host, port)
            except (OSError, TimeoutError) as e:
                if verbose:
                    print(f"[proxy] tunnel stream failed: {e}")
                browser_sock.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                return
            relay_over_tunnel(tunnel, browser_sock, stream_id, forward_headers + leftover)
            return

        browser_sock.sendall(b"HTTP/1.1 400 Bad Request\r\n\r\n")
    except Exception as e:
        if verbose:
            print(f"[proxy] error: {e}")
    finally:
        try:
            browser_sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        browser_sock.close()


def run_local_proxy(
    scattered: Scattered,
    *,
    host="127.0.0.1",
    port=8080,
    verbose=False,
):
    scattered.prepare_network()
    tunnel = SharedTunnel(scattered, verbose=verbose)
    tunnel.start()
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((host, port))
    server.listen(128)
    print(f"Onion proxy listening on {host}:{port}")
    print("Shared onion tunnel active — new sites reuse the same circuit.")
    print(f"Onion network via registry at {scattered.registry_host}:{scattered.registry_port}")
    try:
        while True:
            browser_sock, addr = server.accept()
            threading.Thread(
                target=_handle_connection,
                args=(browser_sock, tunnel),
                kwargs={"verbose": verbose},
                daemon=True,
            ).start()
    except KeyboardInterrupt:
        print("\nProxy stopped.")
    finally:
        server.close()


def main():
    import argparse
    from src.client import create

    parser = argparse.ArgumentParser(description="OnionSocket HTTP proxy")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--network-host", default=None)
    parser.add_argument("--registry-host", default=None)
    parser.add_argument("--registry-port", type=int, default=10000)
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    remote = args.network_host or DEFAULT_HOST
    scattered = create(
        network_host=remote,
        registry_host=args.registry_host or remote,
        registry_port=args.registry_port,
        insecure=True,
    )
    run_local_proxy(scattered, host=args.host, port=args.port, verbose=args.verbose)


if __name__ == "__main__":
    main()
