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

resolve_secret_value() {
  local key="$1" required="${2:-required}"
  local direct file_ref relative host_file byte_count value
  direct="$(env_value "$key")"
  file_ref="$(env_value "${key}_FILE")"

  if [[ -n "$direct" && -n "$file_ref" ]]; then
    err "$key: source_conflict"
    exit 1
  fi
  if [[ -n "$direct" ]]; then
    printf '%s' "$direct"
    return 0
  fi
  if [[ -z "$file_ref" ]]; then
    if [[ "$required" == "required" ]]; then
      err "$key: missing_source"
      exit 1
    fi
    return 0
  fi
  if [[ "$file_ref" != /run/secrets/* ]]; then
    err "$key: outside_allowed_root"
    exit 1
  fi
  relative="${file_ref#/run/secrets/}"
  if [[ -z "$relative" || "$relative" == /* || "$relative" == *".."* ]]; then
    err "$key: invalid_file_reference"
    exit 1
  fi
  host_file="$secrets_dir/$relative"
  if [[ -L "$host_file" ]]; then
    err "$key: symlink_forbidden"
    exit 1
  fi
  if [[ ! -f "$host_file" ]]; then
    err "$key: file_missing"
    exit 1
  fi
  if find "$host_file" -prune -perm /077 -print -quit | grep -q .; then
    err "$key: insecure_permissions"
    exit 1
  fi
  byte_count="$(wc -c <"$host_file")"
  if (( byte_count == 0 )); then
    err "$key: empty_value"
    exit 1
  fi
  if (( byte_count > 16384 )); then
    err "$key: file_too_large"
    exit 1
  fi
  value="$(<"$host_file")"
  while [[ "$value" == *$'\r' ]]; do
    value="${value%$'\r'}"
  done
  if [[ -z "$value" ]]; then
    err "$key: empty_value"
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
    err "$key: unexpected_value"
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

secrets_dir="$(env_value ISCY_SECRETS_DIR)"
secrets_dir="${secrets_dir:-./.runtime/secrets}"
database_url="$(resolve_secret_value DATABASE_URL)"
postgres_password="$(resolve_secret_value POSTGRES_PASSWORD)"
alert_token="$(resolve_secret_value ISCY_ALERTMANAGER_TOKEN)"
reject_placeholder DATABASE_URL "$database_url"
reject_placeholder POSTGRES_PASSWORD "$postgres_password"
reject_placeholder ISCY_ALERTMANAGER_TOKEN "$alert_token"

if (( ${#alert_token} < 24 )); then
  err "ISCY_ALERTMANAGER_TOKEN: value_too_short"
  exit 1
fi

for optional_key in \
  NVD_API_KEY \
  ISCY_INITIAL_ADMIN_PASSWORD \
  ISCY_ALERTMANAGER_HMAC_SECRET \
  ISCY_EVIDENCE_OBJECT_STORAGE_ACCESS_KEY \
  ISCY_EVIDENCE_OBJECT_STORAGE_SECRET_KEY; do
  optional_value="$(resolve_secret_value "$optional_key" optional)"
  if [[ -n "$optional_value" ]]; then
    reject_placeholder "$optional_key" "$optional_value"
  fi
done

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
