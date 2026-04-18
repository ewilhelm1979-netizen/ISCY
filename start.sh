#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$PROJECT_DIR"

info() { printf '\033[1;34m[INFO]\033[0m %s\n' "$1"; }
warn() { printf '\033[1;33m[WARN]\033[0m %s\n' "$1"; }
err()  { printf '\033[1;31m[ERR ]\033[0m %s\n' "$1" >&2; }

if [ ! -d ".venv" ]; then
  info "Erstelle virtuelle Umgebung (.venv) mit --copies ..."
  python3 -m venv --copies .venv
fi

# shellcheck disable=SC1091
source .venv/bin/activate
python -c "import sys, encodings; print('Python OK:', sys.executable)" >/dev/null

VERIFY_LOCAL_LLM="${VERIFY_LOCAL_LLM:-0}"
LOCAL_LLM_RUST_URL="${LOCAL_LLM_RUST_URL:-http://127.0.0.1:9000}"
RUST_BACKEND_URL="${RUST_BACKEND_URL:-$LOCAL_LLM_RUST_URL}"

if [ ! -f ".env" ] && [ -f ".env.example" ]; then
  cp .env.example .env
  info ".env aus .env.example erstellt."
fi

set_env_var() {
  local key="$1" value="$2"
  python - "$key" "$value" <<'PY'
import sys
from pathlib import Path
key = sys.argv[1]
value = sys.argv[2]
p = Path('.env')
lines = p.read_text().splitlines() if p.exists() else []
out = []
found = False
for line in lines:
    if line.startswith(f"{key}="):
        out.append(f"{key}={value}")
        found = True
    else:
        out.append(line)
if not found:
    out.append(f"{key}={value}")
p.write_text("\n".join(out) + "\n")
PY
}

rust_backend_reachable() {
  curl -fsS --max-time 2 "$RUST_BACKEND_URL/health" >/dev/null 2>&1
}

mkdir -p static media staticfiles models

info "Aktualisiere pip ..."
python -m pip install --upgrade pip

info "Installiere Basis-Abhängigkeiten ..."
python -m pip install -r requirements.txt

info "Konfiguriere Rust-Backend als Standard für LLM/Vuln-Scoring ..."
set_env_var "LOCAL_LLM_BACKEND" "rust_service"
set_env_var "LOCAL_LLM_RUST_URL" "$LOCAL_LLM_RUST_URL"
set_env_var "RUST_BACKEND_URL" "$RUST_BACKEND_URL"
set_env_var "RISK_SCORING_BACKEND" "rust_service"
set_env_var "GUIDANCE_SCORING_BACKEND" "rust_service"
set_env_var "REPORT_SUMMARY_BACKEND" "rust_service"

if rust_backend_reachable; then
  info "Rust-Backend erreichbar unter $RUST_BACKEND_URL. Aktiviere Local-LLM-Flow."
  set_env_var "LOCAL_LLM_ENABLED" "True"
else
  warn "Rust-Backend unter $RUST_BACKEND_URL aktuell nicht erreichbar."
  warn "LLM-Enrichment bleibt deaktiviert, bis der Service läuft (make rust-run)."
  set_env_var "LOCAL_LLM_ENABLED" "False"
fi

info "Führe Migrationen und Seeds aus ..."
python manage.py makemigrations
python manage.py migrate
python manage.py seed_demo || true
python manage.py seed_catalog || true
python manage.py seed_requirements || true
python manage.py seed_product_security || true

if [ "$VERIFY_LOCAL_LLM" = "1" ]; then
  if rust_backend_reachable; then
    info "Prüfe Rust-LLM per Django-Command ..."
    python manage.py check_local_llm --generate || {
      err "LLM-Selbsttest fehlgeschlagen. Starte App nicht automatisch."
      exit 1
    }
  else
    warn "VERIFY_LOCAL_LLM=1 gesetzt, aber Rust-Backend ist nicht erreichbar; Test wird übersprungen."
  fi
fi

info "Prüfe Django-Konfiguration ..."
python manage.py check

info "Starte Django-Server ..."
python manage.py runserver
