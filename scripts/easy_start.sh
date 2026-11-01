#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$PROJECT_DIR"

usage() {
  printf '%s\n' 'ISCY: ./scripts/easy_start.sh [--native [demo|run|check]|--compose [start|check]|--help]' \
    'Ohne Argumente: Compose falls vorhanden, sonst nativer Demo-Start.'
}

engine=auto
mode=start
case "${1:-}" in
  --help|-h) [ "$#" -eq 1 ] || exit 64; usage; exit 0 ;;
  --native|--compose) engine="${1#--}"; shift; mode="${1:-start}"; [ "$#" -eq 0 ] || shift ;;
  '') ;;
  *) usage >&2; exit 64 ;;
esac
[ "$#" -eq 0 ] || { usage >&2; exit 64; }
case "$engine:$mode" in
  native:start|native:demo|native:run|native:check|compose:start|compose:check|auto:start) ;;
  *) usage >&2; exit 64 ;;
esac

if [ "$engine" = auto ]; then
  if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
    engine=compose
  else
    engine=native
  fi
fi
if [ "$engine" = native ]; then
  [ "$mode" != start ] || mode=demo
  exec ./start.sh "$mode"
fi

# A failed preflight must never be followed by startup or another engine.
make docker-check
[ "$mode" != check ] || exit 0
exec make dev-up
