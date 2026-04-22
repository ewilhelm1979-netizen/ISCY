#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$PROJECT_DIR"

info() { printf '\033[1;34m[INFO]\033[0m %s\n' "$1"; }
warn() { printf '\033[1;33m[WARN]\033[0m %s\n' "$1"; }
err()  { printf '\033[1;31m[ERR ]\033[0m %s\n' "$1" >&2; }

if [ ! -f ".env" ] && [ -f ".env.example" ]; then
  cp .env.example .env
  info ".env aus .env.example erstellt."
fi

env_file_value() {
  local key="$1"
  if [ -f ".env" ]; then
    awk -F= -v key="$key" '$1 == key { sub(/^[^=]*=/, ""); print; exit }' .env
  fi
}

set_env_var() {
  local key="$1" value="$2" tmp
  tmp="$(mktemp)"
  if [ -f ".env" ]; then
    awk -v key="$key" -v value="$value" '
      BEGIN { found = 0 }
      $0 ~ "^" key "=" {
        print key "=" value
        found = 1
        next
      }
      { print }
      END {
        if (!found) {
          print key "=" value
        }
      }
    ' .env >"$tmp"
  else
    printf '%s=%s\n' "$key" "$value" >"$tmp"
  fi
  mv "$tmp" .env
}

env_database_url="$(env_file_value DATABASE_URL || true)"
DATABASE_URL="${DATABASE_URL:-${env_database_url:-sqlite:///db.sqlite3}}"
RUST_BACKEND_BIND="${RUST_BACKEND_BIND:-127.0.0.1:9000}"

bind_host="${RUST_BACKEND_BIND%:*}"
bind_port="${RUST_BACKEND_BIND##*:}"
if [ "$bind_host" = "0.0.0.0" ]; then
  bind_host="127.0.0.1"
fi
RUST_BACKEND_URL="${RUST_BACKEND_URL:-http://$bind_host:$bind_port}"
LOCAL_LLM_RUST_URL="${LOCAL_LLM_RUST_URL:-$RUST_BACKEND_URL}"

export DATABASE_URL
export RUST_BACKEND_BIND
export RUST_BACKEND_URL
export LOCAL_LLM_RUST_URL
export RUST_ONLY_MODE=True
export RUST_STRICT_MODE=True

set_env_var "DATABASE_URL" "$DATABASE_URL"
set_env_var "RUST_BACKEND_URL" "$RUST_BACKEND_URL"
set_env_var "LOCAL_LLM_RUST_URL" "$LOCAL_LLM_RUST_URL"
set_env_var "LOCAL_LLM_BACKEND" "rust_service"
set_env_var "RISK_SCORING_BACKEND" "rust_service"
set_env_var "GUIDANCE_SCORING_BACKEND" "rust_service"
set_env_var "REPORT_SUMMARY_BACKEND" "rust_service"
set_env_var "REPORT_SNAPSHOT_BACKEND" "rust_service"
set_env_var "DASHBOARD_SUMMARY_BACKEND" "rust_service"
set_env_var "CATALOG_BACKEND" "rust_service"
set_env_var "REQUIREMENTS_BACKEND" "rust_service"
set_env_var "ASSET_INVENTORY_BACKEND" "rust_service"
set_env_var "PROCESS_REGISTER_BACKEND" "rust_service"
set_env_var "RISK_REGISTER_BACKEND" "rust_service"
set_env_var "EVIDENCE_REGISTER_BACKEND" "rust_service"
set_env_var "ASSESSMENT_REGISTER_BACKEND" "rust_service"
set_env_var "ROADMAP_REGISTER_BACKEND" "rust_service"
set_env_var "WIZARD_RESULTS_BACKEND" "rust_service"
set_env_var "IMPORT_CENTER_BACKEND" "rust_service"
set_env_var "PRODUCT_SECURITY_BACKEND" "rust_service"
set_env_var "RUST_ONLY_MODE" "True"
set_env_var "RUST_STRICT_MODE" "True"

run_backend() {
  if [ -n "${ISCY_BACKEND_BIN:-}" ]; then
    "$ISCY_BACKEND_BIN" "$@"
  elif command -v nix >/dev/null 2>&1; then
    nix run .#iscy-backend -- "$@"
  elif command -v cargo >/dev/null 2>&1; then
    cargo run --manifest-path rust/iscy-backend/Cargo.toml --bin iscy-backend -- "$@"
  else
    err "Weder nix noch cargo gefunden. Bitte nix develop nutzen oder Rust installieren."
    exit 1
  fi
}

info "ISCY startet im Rust-only-Modus."
info "DATABASE_URL=$DATABASE_URL"
info "RUST_BACKEND_BIND=$RUST_BACKEND_BIND"

if [ "${ISCY_SKIP_INIT_DEMO:-0}" != "1" ]; then
  info "Initialisiere Rust-Datenbank und Demo-/Katalog-Seeds ..."
  run_backend init-demo
else
  warn "ISCY_SKIP_INIT_DEMO=1 gesetzt; Rust-DB-Initialisierung wird uebersprungen."
fi

info "Starte Rust-Backend unter $RUST_BACKEND_URL ..."
if [ -n "${ISCY_BACKEND_BIN:-}" ]; then
  exec "$ISCY_BACKEND_BIN"
elif command -v nix >/dev/null 2>&1; then
  exec nix run .#iscy-backend
else
  exec cargo run --manifest-path rust/iscy-backend/Cargo.toml --bin iscy-backend
fi
