# OnionSocket

A small Python lab for onion-style routing over TCP. Traffic hops through relay nodes before reaching an exit node. Messages are end-to-end encrypted so relays only peel routing layers — they never see the plaintext.

Built for learning: directory registration, circuit building, padded payloads, a socket-style server API, and **web browsing** through a local HTTP proxy.

## Requirements

- **Python 3.10+** (developed and tested on **Python 3.12**)
- `cryptography` (see `requirements.txt`)

```bash
python3 --version   # should be 3.10 or newer
pip install -r requirements.txt
```

## Project layout

```
OnionSocket/
├── start_network.sh     # start/stop the full network (+ optional web proxy)
├── registry.py          # directory server (relay + exit registry)
├── node.py              # relay node CLI
├── exit.py              # exit node CLI (web proxy enabled by default)
├── server.py            # optional session API demo (--as-exit)
├── client.py            # client example / local web proxy
└── src/
    ├── client/          # Scattered client (create, send, open_stream, close)
    ├── node/            # RelayNode + ExitNode
    ├── proxy/           # local HTTP CONNECT proxy + exit stream relay
    ├── server/          # exit node API + directory
    └── core/            # onion, e2e crypto, discovery, protocol, tunnel mux
```

## How it fits together

**Chat / message mode** — one onion circuit per message:

```
client  →  relay  →  relay  →  relay  →  exit node
              ↑         ↑         ↑
         peel onion layers (cannot read message)
```

**Web browsing** — one shared onion tunnel, many browser connections multiplexed over it:

```
browser  →  local proxy (:8080)  →  relay  →  relay  →  relay  →  exit  →  internet
                ↑
           shared onion circuit (new tabs reuse the same tunnel)
```

1. **Directory** (`registry.py`) — relay and exit nodes register here. The client fetches the list to build circuits.
2. **Relay nodes** (`node.py`) — forward onion traffic, peeling one layer per hop.
3. **Exit node** (`exit.py`) — final hop; decrypts traffic and either relays messages (chat mode) or streams TCP to destinations (web proxy mode).
4. **Client** (`client.py`) — builds onion circuits. In proxy mode, runs a local HTTP CONNECT proxy for browser traffic.

Default ports (with 3 relays):

| Service     | Port  |
|-------------|-------|
| Directory   | 10000 |
| Relay 1     | 10001 |
| Relay 2     | 10002 |
| Relay 3     | 10003 |
| Exit        | 10004 |
| Web proxy   | 8080  |

## Quick start

### One command (recommended)

Start the directory, three relays, exit node, and local web proxy:

```bash
./start_network.sh --proxy
```

Other commands:

```bash
./start_network.sh status    # show running services
./start_network.sh logs      # tail service logs
./start_network.sh stop      # stop everything
./start_network.sh restart --proxy
```

Logs and PID files are written to `.onionsocket-logs/` and `.onionsocket-pids/`.

### Web browsing

With the proxy running, configure your browser to use **HTTP** proxy `127.0.0.1:8080` (not HTTPS proxy).

**FoxyProxy example:**

| Setting  | Value        |
|----------|--------------|
| Type     | HTTP         |
| Host     | `127.0.0.1`  |
| Port     | `8080`       |
| Pattern  | `*://*/*`    |
| Username | *(leave blank)* |
| Password | *(leave blank)* |

Do **not** browse to `https://localhost:8080` — set the proxy in your browser or extension instead.

Traffic path: `browser → local proxy → onion relays → exit → destination`.

When the network runs on another machine, pass its LAN IP:

```bash
python3 client.py --proxy --network-host 192.168.1.100
```

To run the proxy manually (network already up):

```bash
python3 client.py --proxy
```

The exit node enables web streaming by default. Use `--no-proxy` on `exit.py` for chat/message mode only.

### Manual setup (six terminals)

Open **six terminals** from the project root (directory, 3 relays, exit node, client).

**Terminal 1 — directory**

```bash
python3 registry.py
```

**Terminals 2–4 — relay nodes** (one per terminal)

```bash
python3 node.py --port 10001
python3 node.py --port 10002
python3 node.py --port 10003
```

Each node opens a **green terminal dashboard** with live traffic charts. Use **←/→** to switch panels, **↑/↓** to scroll, **Q** to quit. Add `--plain` for the old text-only logs.

**Terminal 5 — exit node**

```bash
python3 exit.py --plain
```

Web streaming is enabled by default. Add `--no-proxy` to disable it.

`server.py` runs the application server (sessions, echo). The onion exit is `exit.py` — the client discovers it from the directory. Use `server.py --as-exit` only if you want one process to do both.

**Terminal 6 — client**

```bash
python3 client.py
```

For web browsing from a separate terminal (if not using `start_network.sh --proxy`):

```bash
python3 client.py --proxy
```

## Quick demo

Expected flow when everything is running:

**Exit node** (terminal 5):

```
Exit node 127.0.0.1:10004
Secure mode
Listening on 0.0.0.0:10004
Registered with directory localhost:10000
Connection #1 from 127.0.0.1:...
New session client-1
[client-1] hello
Active sessions:
  client-1 (127.0.0.1:..., 1 messages)
Connection #2 from 127.0.0.1:...
[client-1] second message
Active sessions:
  client-1 (127.0.0.1:..., 2 messages)
Connection #3 from 127.0.0.1:...
client-1 disconnected (client disconnected from 127.0.0.1:...)
Active sessions: none
```

**Client** (terminal 6):

```
You: hello
  circuit: 10002 -> 10001 -> 10003 -> 10004
Server: hello
You: second message
  circuit: 10003 -> 10002 -> 10001 -> 10004
Server: second message
Connection closed
```

Each message uses a **new random circuit** (secure mode). The server still recognises the same client as `client-1` via their public key until `client.close()` runs.

## Using the API

### Client

```python
from src import client

s = client.create()  # uses all relays from registry

replies = client.send(s, b"hello")
for reply in replies:
    print(reply.decode())

client.close(s)   # notifies server (CLIENT_CLOSE)
```

### Server (socket-style)

Same pattern as Python TCP sockets:

```python
from src.server import create_exit_node, listen, accept, receive, send, close

srv = create_exit_node(port=10004)
listen(srv)

conn = accept(srv)                        # blocks until a client connects
message = receive(srv, conn)              # read decrypted message
send(srv, conn, message)                  # reply on this connection
close(conn)

# Sessions — track clients across connections
conn.session.label      # "client-1"
list_sessions(srv)      # all known clients
```

CLI with more options:

```bash
python3 -m src.client --server-host localhost --server-port 10004 --nodes 3 --send "hello"
python3 -m src.server --port 10004
```

## Sessions

Secure mode opens a **new TCP connection per message**, but the server keeps a **session per client public key**:

- `conn.conn_id` — this TCP connection (`#1`, `#2`, …)
- `conn.session.sid` — stable client id (`client-1`, `client-2`, …)

Queue a reply for a client's next message:

```python
from src.server import queue

queue(srv, "see you later", session=conn.session)
# or
queue(srv, "see you later", sid=1)
```

## Connecting from another machine (e.g. Windows → Mac)
**NOT TESTED ON LINUX: TESTED ONLY ON WINDOWS AND MACOS**

  
Everything (directory, relays, exit) must run on the **Mac**. Nodes bind to `0.0.0.0` so they accept LAN connections.

On the **Windows** client, point at the Mac's LAN IP for **all** discovery — not just the exit:

```python
s = client.create(
    network_host="192.168.1.100",  # Mac LAN IP
    server_port=10004,
)
```

`network_host` points the client at the Mac's directory registry (port 10000). Relays and the exit are fetched from there — no port scanning.

**Checklist if it still fails:**

1. Mac firewall allows incoming Python (System Settings → Network → Firewall)
2. `registry.py`, 3× `node.py`, and `exit.py` are all running on the Mac
3. From Windows: `ping 192.168.1.100` works
4. Mac and Windows are on the same subnet (both `192.168.1.x`)

## Windows

- **Client** works on Windows (Python 3.10+ and `cryptography`)
- **Relay/exit dashboards** fall back to plain text logs (curses is not used on Windows)
- Run nodes with `--plain` on Windows: `python node.py --port 10001 --plain`

## Notes

- This is a **lab project**, not production Tor. The last relay sees the server; return traffic is not re-onioned.
- Server and nodes bind to `0.0.0.0` by default so they work on LAN; the directory stores an advertised host for discovery.
- If ports are already in use, run `./start_network.sh stop` or change ports via the script flags / CLI options.
- Some sites (Google, YouTube) load many subdomains in parallel; the shared tunnel handles these as separate multiplexed streams over one onion circuit.
- If browsing fails after idle time, restart with `./start_network.sh restart --proxy`.
