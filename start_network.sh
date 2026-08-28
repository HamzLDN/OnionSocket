#!/usr/bin/env bash
# Start or stop the full OnionSocket network (registry, relays, exit, optional proxy).
#
# Usage:
#   ./start_network.sh          # start registry + 3 relays + exit
#   ./start_network.sh --proxy  # also start the local web proxy on :8080
#   ./start_network.sh stop     # stop everything started by this script
#   ./start_network.sh status   # show what's running
#   ./start_network.sh logs     # tail all logs

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PID_DIR="$ROOT/.onionsocket-pids"
LOG_DIR="$ROOT/.onionsocket-logs"
PYTHON="${PYTHON:-python3}"
export PYTHONUNBUFFERED=1

REGISTRY_PORT="${REGISTRY_PORT:-10000}"
RELAY_PORTS=(10001 10002 10003)
EXIT_PORT="${EXIT_PORT:-10004}"
PROXY_PORT="${PROXY_PORT:-8080}"
PROXY_HOST="${PROXY_HOST:-127.0.0.1}"

START_PROXY=0
CMD="start"

usage() {
  cat <<EOF
Usage: $(basename "$0") [command] [options]

Commands:
  start     Start the network (default)
  stop      Stop all services started by this script
  restart   Stop then start
  status    Show running services
  logs      Tail service logs

Options:
  --proxy         Also start the local HTTP proxy (client.py --proxy)
  --registry-port PORT   Registry port (default: $REGISTRY_PORT)
  --exit-port PORT       Exit port (default: $EXIT_PORT)
  --proxy-port PORT      Local proxy port (default: $PROXY_PORT)
  -h, --help      Show this help

Examples:
  ./start_network.sh
  ./start_network.sh --proxy
  ./start_network.sh stop
EOF
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      start|stop|restart|status|logs)
        CMD="$1"
        shift
        ;;
      --proxy)
        START_PROXY=1
        shift
        ;;
      --registry-port)
        REGISTRY_PORT="$2"
        shift 2
        ;;
      --exit-port)
        EXIT_PORT="$2"
        shift 2
        ;;
      --proxy-port)
        PROXY_PORT="$2"
        shift 2
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      *)
        echo "Unknown option: $1" >&2
        usage >&2
        exit 1
        ;;
    esac
  done
}

mkdir -p "$PID_DIR" "$LOG_DIR"

pid_file() { echo "$PID_DIR/$1.pid"; }
log_file() { echo "$LOG_DIR/$1.log"; }

is_running() {
  local pid
  pid="$(cat "$(pid_file "$1")" 2>/dev/null || true)"
  [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null
}

start_service() {
  local name="$1"
  shift

  if is_running "$name"; then
    echo "  $name already running (pid $(cat "$(pid_file "$name")"))"
    return 0
  fi

  : > "$(log_file "$name")"
  (
    cd "$ROOT"
    exec "$PYTHON" "$@"
  ) >> "$(log_file "$name")" 2>&1 &

  echo $! > "$(pid_file "$name")"
  echo "  $name started (pid $(cat "$(pid_file "$name")"), log: $(log_file "$name"))"
}

stop_service() {
  local name="$1"
  if ! is_running "$name"; then
    rm -f "$(pid_file "$name")"
    return 0
  fi
  local pid
  pid="$(cat "$(pid_file "$name")")"
  kill "$pid" 2>/dev/null || true
  for _ in $(seq 1 20); do
    kill -0 "$pid" 2>/dev/null || break
    sleep 0.2
  done
  if kill -0 "$pid" 2>/dev/null; then
    kill -9 "$pid" 2>/dev/null || true
  fi
  rm -f "$(pid_file "$name")"
  echo "  stopped $name"
}

wait_for_port() {
  local port="$1"
  local label="$2"
  local tries="${3:-30}"
  for _ in $(seq 1 "$tries"); do
    if "$PYTHON" -c "
import socket
s = socket.socket()
s.settimeout(0.5)
try:
    s.connect(('127.0.0.1', $port))
    s.close()
    raise SystemExit(0)
except OSError:
    raise SystemExit(1)
" 2>/dev/null; then
      return 0
    fi
    sleep 0.5
  done
  echo "  warning: $label not listening on port $port yet" >&2
  return 1
}

wait_for_exit_in_registry() {
  local tries="${1:-20}"
  for _ in $(seq 1 "$tries"); do
    if "$PYTHON" -c "
from src.core.registry_client import list_services
_, servers = list_services(registry_port=$REGISTRY_PORT)
raise SystemExit(0 if servers else 1)
" 2>/dev/null; then
      return 0
    fi
    sleep 0.5
  done
  echo "  warning: exit not registered in directory yet" >&2
  return 1
}

do_start() {
  echo "Starting OnionSocket network..."
  echo "  project: $ROOT"
  echo

  start_service registry registry.py --port "$REGISTRY_PORT"
  wait_for_port "$REGISTRY_PORT" "registry" 20 || true

  for port in "${RELAY_PORTS[@]}"; do
    start_service "relay-$port" node.py --port "$port" --plain --registry-port "$REGISTRY_PORT"
  done

  start_service exit exit.py --plain --port "$EXIT_PORT" --registry-port "$REGISTRY_PORT" --verbose
  wait_for_port "$EXIT_PORT" "exit" 20 || true
  wait_for_exit_in_registry 20 || true

  if [[ "$START_PROXY" -eq 1 ]]; then
    if ! is_running proxy; then
      stale="$(lsof -ti :"$PROXY_PORT" 2>/dev/null || true)"
      if [[ -n "$stale" ]]; then
        echo "  freeing stale process on port $PROXY_PORT (pid $stale)"
        kill $stale 2>/dev/null || true
        sleep 0.5
      fi
    fi
    start_service proxy client.py --proxy --verbose --registry-port "$REGISTRY_PORT" --proxy-host "$PROXY_HOST" --proxy-port "$PROXY_PORT"
    wait_for_port "$PROXY_PORT" "proxy" 20 || true
  fi

  echo
  echo "Network is up."
  echo "  Directory : localhost:$REGISTRY_PORT"
  echo "  Relays    : ${RELAY_PORTS[*]}"
  echo "  Exit      : localhost:$EXIT_PORT"
  if [[ "$START_PROXY" -eq 1 ]]; then
    echo "  Web proxy : $PROXY_HOST:$PROXY_PORT  (set browser HTTP proxy to this)"
  else
    echo
    echo "To start the web proxy:"
    echo "  ./start_network.sh --proxy"
    echo "  # or: python3 client.py --proxy"
  fi
  echo
  echo "Stop everything: ./start_network.sh stop"
  echo "View logs:       ./start_network.sh logs"
}

do_stop() {
  echo "Stopping OnionSocket network..."
  stop_service proxy
  stop_service exit
  for port in "${RELAY_PORTS[@]}"; do
    stop_service "relay-$port"
  done
  stop_service registry
  echo "Done."
}

do_status() {
  local names=(registry)
  for port in "${RELAY_PORTS[@]}"; do names+=("relay-$port"); done
  names+=(exit proxy)
  for name in "${names[@]}"; do
    if is_running "$name"; then
      printf "  %-12s running (pid %s)\n" "$name" "$(cat "$(pid_file "$name")")"
    else
      printf "  %-12s stopped\n" "$name"
    fi
  done
}

do_logs() {
  tail -f "$LOG_DIR"/*.log
}

parse_args "$@"

case "$CMD" in
  start) do_start ;;
  stop) do_stop ;;
  restart) do_stop; sleep 1; do_start ;;
  status) do_status ;;
  logs) do_logs ;;
esac
