#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

ENV_FILE="${ENV_FILE:-.env.production}"
BACKUP_DIR="${BACKUP_DIR:-$ROOT_DIR/backups}"
STAMP="$(date +%Y%m%d-%H%M%S)"
TARGET_DIR="$BACKUP_DIR/$STAMP"
mkdir -p "$TARGET_DIR"

if [[ -f "$ENV_FILE" ]]; then
  set -a
  # shellcheck disable=SC1090
  source "$ENV_FILE"
  set +a
fi

COMPOSE_ARGS=(-f docker-compose.yml -f docker-compose.prod.yml)
if [[ "${WITH_LLM:-0}" == "1" ]]; then
  COMPOSE_ARGS+=(-f docker-compose.llm.yml)
fi

POSTGRES_USER="${POSTGRES_USER:-isms}"
POSTGRES_DB="${POSTGRES_DB:-isms}"

printf '[backup] writing into %s\n' "$TARGET_DIR"

docker compose "${COMPOSE_ARGS[@]}" exec -T db \
  pg_dump -U "$POSTGRES_USER" "$POSTGRES_DB" | gzip -c > "$TARGET_DIR/postgres.sql.gz"

docker compose "${COMPOSE_ARGS[@]}" run --rm --entrypoint sh app \
  -lc 'mkdir -p /app/media /app/staticfiles /app/models && tar -C /app -czf - media staticfiles models 2>/dev/null || true' \
  > "$TARGET_DIR/storage.tar.gz"

if [[ -f "$ENV_FILE" ]]; then
  cp "$ENV_FILE" "$TARGET_DIR/env.snapshot"
fi

printf '[backup] done: %s\n' "$TARGET_DIR"
