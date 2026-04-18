#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$PROJECT_DIR"

info() { printf '\033[1;34m[INFO]\033[0m %s\n' "$1"; }
warn() { printf '\033[1;33m[WARN]\033[0m %s\n' "$1"; }

if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
  info "Docker erkannt. Starte den einfachsten Compose-Flow (dev-up)."
  make docker-check || warn "docker-check fehlgeschlagen, versuche trotzdem dev-up."
  exec make dev-up
fi

warn "Docker nicht verfügbar. Fallback auf lokalen Python-Start (start.sh)."
info "Hinweis: Lokaler Start nutzt virtuelle Umgebung, Migrationen und runserver."
exec ./start.sh
