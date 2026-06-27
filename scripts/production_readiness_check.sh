#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$PROJECT_DIR"

info() { printf '\033[1;34m[INFO]\033[0m %s\n' "$1"; }
warn() { printf '\033[1;33m[WARN]\033[0m %s\n' "$1"; }
err()  { printf '\033[1;31m[ERR ]\033[0m %s\n' "$1" >&2; }

ENV_FILE="${ENV_FILE:-.env.production}"

if [[ ! -f "$ENV_FILE" ]]; then
  err "$ENV_FILE fehlt. Bitte .env.production.example kopieren und produktiv konfigurieren."
  exit 1
fi
if find "$ENV_FILE" -perm /077 -print -quit | grep -q .; then
  err "$ENV_FILE ist fuer Gruppe oder andere Benutzer lesbar. Erwartet wird chmod 600."
  exit 1
fi

env_value() {
  local key="$1"
  awk -F= -v key="$key" '$1 == key { sub(/^[^=]*=/, ""); print; exit }' "$ENV_FILE"
}

require_value() {
  local key="$1" value
  value="$(env_value "$key")"
  if [[ -z "$value" ]]; then
    err "$key fehlt oder ist leer."
    exit 1
  fi
  printf '%s' "$value"
}

reject_placeholder() {
  local key="$1" value="$2" lower
  lower="$(printf '%s' "$value" | tr '[:upper:]' '[:lower:]')"
  if [[ "$lower" == *"replace_with"* || "$lower" == *"change-me"* || "$lower" == *"changeme"* || "$lower" == *"example"* || "$lower" == *"postgresql://isms:isms@"* ]]; then
    err "$key enthaelt noch einen Beispiel- oder Platzhalterwert."
    exit 1
  fi
}

require_exact() {
  local key="$1" expected="$2" actual
  actual="$(env_value "$key")"
  if [[ "$actual" != "$expected" ]]; then
    err "$key muss '$expected' sein, ist aber '${actual:-<leer>}'."
    exit 1
  fi
}

info "Pruefe kritische Produktionsparameter ..."
require_exact ISCY_APP_MODE production
require_exact ISCY_TRUST_PROXY_IDENTITY_HEADERS 0
require_exact ISCY_TRUSTED_PROXY_CONFIGURED 1
require_exact ISCY_SECURE_COOKIES 1

if [[ "$(env_value ISCY_HSTS_ENABLED)" == "1" && "$(env_value ISCY_HTTPS_CONFIRMED)" != "1" ]]; then
  err "ISCY_HSTS_ENABLED=1 erfordert eine tatsaechlich bestaetigte HTTPS-Terminierung."
  exit 1
fi

database_url="$(require_value DATABASE_URL)"
postgres_password="$(require_value POSTGRES_PASSWORD)"
reject_placeholder DATABASE_URL "$database_url"
reject_placeholder POSTGRES_PASSWORD "$postgres_password"

secrets_dir="$(env_value ISCY_SECRETS_DIR)"
secrets_dir="${secrets_dir:-./.runtime/secrets}"
alert_token="$(env_value ISCY_ALERTMANAGER_TOKEN)"
alert_token_file="$(env_value ISCY_ALERTMANAGER_TOKEN_FILE)"

if [[ -n "$alert_token" ]]; then
  reject_placeholder ISCY_ALERTMANAGER_TOKEN "$alert_token"
  if (( ${#alert_token} < 24 )); then
    err "ISCY_ALERTMANAGER_TOKEN muss mindestens 24 Zeichen lang sein."
    exit 1
  fi
else
  if [[ -z "$alert_token_file" ]]; then
    err "ISCY_ALERTMANAGER_TOKEN oder ISCY_ALERTMANAGER_TOKEN_FILE fehlt."
    exit 1
  fi
  host_token_file="$secrets_dir/$(basename "$alert_token_file")"
  if [[ ! -r "$host_token_file" ]]; then
    err "Alertmanager-Token-Datei fehlt oder ist nicht lesbar: $host_token_file"
    exit 1
  fi
  token_length="$(tr -d '\r\n' < "$host_token_file" | wc -c)"
  if (( token_length < 24 )); then
    err "Die Alertmanager-Token-Datei muss mindestens 24 Zeichen enthalten."
    exit 1
  fi
fi

if [[ -d "$secrets_dir" ]] && find "$secrets_dir" -maxdepth 1 -type f -perm /077 -print -quit | grep -q .; then
  err "Mindestens eine Datei in $secrets_dir ist fuer Gruppe oder andere Benutzer lesbar."
  exit 1
fi

if command -v docker >/dev/null 2>&1; then
  info "Validiere Compose-Konfiguration (prod/prod+llm) ..."
  docker compose --env-file "$ENV_FILE" -f docker-compose.yml -f docker-compose.prod.yml config >/dev/null
  docker compose --env-file "$ENV_FILE" -f docker-compose.yml -f docker-compose.prod.yml -f docker-compose.llm.yml config >/dev/null
else
  warn "Docker nicht vorhanden, Compose-Validierung wird uebersprungen."
fi

info "Rust-Backend-Basispruefung ..."
cargo test --locked --manifest-path rust/iscy-backend/Cargo.toml

info "Readiness-Check abgeschlossen."
