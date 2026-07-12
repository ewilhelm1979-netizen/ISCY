#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_DIR="$(mktemp -d)"
DB_PATH="$TMP_DIR/iscy-shutdown.sqlite3"
LOG_FILE="$TMP_DIR/iscy-shutdown.log"
export DATABASE_URL="sqlite:////${DB_PATH#/}"
export RUST_BACKEND_BIND="127.0.0.1:19210"
export ISCY_AGENT_NOTIFICATION_INTERVAL_SECONDS=0
export ISCY_SHUTDOWN_TIMEOUT_SECONDS=10

cleanup() {
  if [[ -n "${backend_pid:-}" ]] && kill -0 "$backend_pid" >/dev/null 2>&1; then
    kill -KILL "$backend_pid" >/dev/null 2>&1 || true
  fi
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT INT TERM

cargo build --locked --manifest-path "$ROOT_DIR/rust/iscy-backend/Cargo.toml" --bin iscy-backend
BACKEND="$ROOT_DIR/rust/iscy-backend/target/debug/iscy-backend"
"$BACKEND" init-demo >/dev/null
"$BACKEND" >"$LOG_FILE" 2>&1 &
backend_pid=$!

for _ in $(seq 1 60); do
  if curl --fail --silent --show-error http://127.0.0.1:19210/health/ready >/dev/null 2>&1; then
    break
  fi
  if ! kill -0 "$backend_pid" >/dev/null 2>&1; then
    cat "$LOG_FILE" >&2
    exit 1
  fi
  sleep 1
done
curl --fail --silent --show-error http://127.0.0.1:19210/health/ready >/dev/null

kill -TERM "$backend_pid"
set +e
wait "$backend_pid"
exit_code=$?
set -e
backend_pid=""
if [[ "$exit_code" -ne 0 ]]; then
  cat "$LOG_FILE" >&2
  echo "Graceful Shutdown endete mit Exitcode $exit_code." >&2
  exit 1
fi

echo "ISCY Graceful-Shutdown-Smoke OK"
