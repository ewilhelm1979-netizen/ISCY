#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <backup-directory>" >&2
  exit 1
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

RESTORE_DIR="$1"
ENV_FILE="${ENV_FILE:-.env.production}"

if [[ ! -d "$RESTORE_DIR" ]]; then
  echo "Backup directory not found: $RESTORE_DIR" >&2
  exit 1
fi

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

echo "[restore] restoring database $POSTGRES_DB"
docker compose "${COMPOSE_ARGS[@]}" exec -T db \
  dropdb -U "$POSTGRES_USER" --if-exists "$POSTGRES_DB"
docker compose "${COMPOSE_ARGS[@]}" exec -T db \
  createdb -U "$POSTGRES_USER" "$POSTGRES_DB"

gunzip -c "$RESTORE_DIR/postgres.sql.gz" | docker compose "${COMPOSE_ARGS[@]}" exec -T db \
  psql -U "$POSTGRES_USER" -d "$POSTGRES_DB"

echo "[restore] restoring media/static/models"
cat "$RESTORE_DIR/storage.tar.gz" | docker compose "${COMPOSE_ARGS[@]}" run --rm --entrypoint sh app \
  -lc 'mkdir -p /app/media /app/staticfiles /app/models && tar -C /app -xzf -'

echo "[restore] done"
