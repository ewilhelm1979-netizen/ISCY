#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$PROJECT_DIR"

info() { printf '\033[1;34m[INFO]\033[0m %s\n' "$1"; }
warn() { printf '\033[1;33m[WARN]\033[0m %s\n' "$1"; }
err()  { printf '\033[1;31m[ERR ]\033[0m %s\n' "$1" >&2; }

if [ ! -f ".env" ]; then
  err ".env fehlt. Bitte .env.production.example nach .env kopieren und produktiv konfigurieren."
  exit 1
fi

info "Pruefe kritische .env-Parameter ..."
if grep -Eq '^SECRET_KEY=change-me-in-production$' .env; then
  err "SECRET_KEY ist noch auf Platzhalterwert."
  exit 1
fi
if grep -Eq '^DEBUG=True$' .env; then
  err "DEBUG=True ist fuer Produktion nicht zulaessig."
  exit 1
fi
if ! grep -Eq '^ALLOWED_HOSTS=.+$' .env; then
  err "ALLOWED_HOSTS fehlt oder ist leer."
  exit 1
fi

if command -v docker >/dev/null 2>&1; then
  info "Validiere Compose-Konfiguration (prod/prod+llm) ..."
  docker compose -f docker-compose.yml -f docker-compose.prod.yml config >/dev/null
  docker compose -f docker-compose.yml -f docker-compose.prod.yml -f docker-compose.llm.yml config >/dev/null
else
  warn "Docker nicht vorhanden, Compose-Validierung wird uebersprungen."
fi

info "Django-Basispruefung ..."
python manage.py check

info "Readiness-Check abgeschlossen."
