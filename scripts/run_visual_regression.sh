#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_DIR="$(mktemp -d)"
DB_PATH="$TMP_DIR/iscy-visual.sqlite3"
LOG_FILE="$TMP_DIR/iscy-visual.log"
export DATABASE_URL="sqlite:////${DB_PATH#/}"
export ISCY_MEDIA_ROOT="$TMP_DIR/media"
export RUST_BACKEND_BIND="127.0.0.1:19200"
export ISCY_VISUAL_BASE_URL="http://127.0.0.1:19200"
export ISCY_AGENT_NOTIFICATION_INTERVAL_SECONDS=0
export TZ=Europe/Berlin
export LANG=de_DE.UTF-8
export LC_ALL=de_DE.UTF-8
export ISCY_VISUAL_ARTIFACT_DIR="${ISCY_VISUAL_ARTIFACT_DIR:-$ROOT_DIR/artifacts/visual}"
export ISCY_VISUAL_REPORT="${ISCY_VISUAL_REPORT:-$ISCY_VISUAL_ARTIFACT_DIR/visual-report.json}"

cleanup() {
  if [[ -n "${backend_pid:-}" ]]; then
    kill -TERM "$backend_pid" >/dev/null 2>&1 || true
    wait "$backend_pid" 2>/dev/null || true
  fi
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT INT TERM

mkdir -p "$ISCY_VISUAL_ARTIFACT_DIR"
cargo run --locked --manifest-path "$ROOT_DIR/rust/iscy-backend/Cargo.toml" \
  --bin iscy-backend -- init-demo >/dev/null
cargo run --locked --manifest-path "$ROOT_DIR/rust/iscy-backend/Cargo.toml" \
  --bin iscy-backend >"$LOG_FILE" 2>&1 &
backend_pid=$!

for _ in $(seq 1 60); do
  if curl --fail --silent --show-error "$ISCY_VISUAL_BASE_URL/health/ready" >/dev/null 2>&1; then
    break
  fi
  if ! kill -0 "$backend_pid" >/dev/null 2>&1; then
    cat "$LOG_FILE" >&2
    exit 1
  fi
  sleep 1
done
curl --fail --silent --show-error "$ISCY_VISUAL_BASE_URL/health/ready" >/dev/null

args=(--config "$ROOT_DIR/tests/visual/playwright.config.js")
if [[ "${ISCY_UPDATE_VISUAL_BASELINES:-0}" == "1" ]]; then
  args+=(--update-snapshots)
fi
playwright test "${args[@]}"

echo "ISCY Visual-Regression-Test OK"
