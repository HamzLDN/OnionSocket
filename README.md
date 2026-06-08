# OnionSocket

A small Python lab for onion-style routing over TCP. Traffic hops through relay nodes before reaching an exit node. Messages are end-to-end encrypted so relays only peel routing layers — they never see the plaintext.

Built for learning: directory registration, circuit building, padded payloads, and a socket-style server API.

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
├── registry.py          # directory server (relay + exit registry)
├── node.py              # relay node CLI
├── exit.py              # exit node CLI
├── server.py            # optional session API demo (--as-exit)
├── client.py            # client example
└── src/
    ├── client/          # Scattered client (create, send, receive, close)
    ├── node/            # RelayNode + ExitNode
    ├── server/          # exit node API + directory
    └── core/            # onion, e2e crypto, discovery, protocol
```

## How it fits together

```
client  →  relay  →  relay  →  relay  →  exit node
              ↑         ↑         ↑
         peel onion layers (cannot read message)
```

1. **Directory** (`registry.py`) — relay and exit nodes register here. The client fetches the list to build circuits.
2. **Relay nodes** (`node.py`) — forward onion traffic, peeling one layer per hop.
3. **Exit node** (`exit.py`) — core final hop; decrypts E2E traffic, handles messages, sends replies.
4. **Client** (`client.py`) — picks random relays, builds a fresh onion per message (secure mode).

Default ports (with 3 relays):

| Service   | Port  |
|-----------|-------|
| Directory | 10000 |
| Relay 1   | 10001 |
| Relay 2   | 10002 |
| Relay 3   | 10003 |
| Exit      | 10004 |

## Quick start

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
python3 exit.py
```

`server.py` runs the application server (sessions, echo). The onion exit is `exit.py` — the client discovers it from the directory. Use `server.py --as-exit` only if you want one process to do both.

**Terminal 6 — client**

```bash
python3 client.py
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

s = client.create(nodes=3)

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

## Notes

- This is a **lab project**, not production Tor. The last relay sees the server; return traffic is not re-onioned.
- Server and nodes bind to `0.0.0.0` by default so they work on LAN; the directory stores an advertised host for discovery.
- If ports are already in use, stop old processes or change ports in `exit.py` / `server.py` / `client.py` to match.
