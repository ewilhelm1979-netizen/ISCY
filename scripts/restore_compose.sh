#!/usr/bin/env bash
set -euo pipefail
umask 077

if [[ $# -lt 1 ]]; then
  echo "Usage: ISCY_RESTORE_CONFIRM=YES $0 <backup-directory>" >&2
  exit 1
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

RESTORE_DIR="$1"
ENV_FILE="${ENV_FILE:-.env.production}"

if [[ "${ISCY_RESTORE_CONFIRM:-}" != "YES" ]]; then
  echo "Restore is destructive. Set ISCY_RESTORE_CONFIRM=YES to continue." >&2
  exit 1
fi
if [[ ! -d "$RESTORE_DIR" ]]; then
  echo "Backup directory not found: $RESTORE_DIR" >&2
  exit 1
fi
if [[ ! -f "$ENV_FILE" ]]; then
  echo "Environment file not found: $ENV_FILE" >&2
  exit 1
fi

for required_file in postgres.sql.gz storage.tar.gz manifest.txt SHA256SUMS; do
  if [[ ! -f "$RESTORE_DIR/$required_file" ]]; then
    echo "Backup file missing: $RESTORE_DIR/$required_file" >&2
    exit 1
  fi
done

(
  cd "$RESTORE_DIR"
  sha256sum -c SHA256SUMS
  gzip -t postgres.sql.gz
  tar -tzf storage.tar.gz >/dev/null
)

set -a
# shellcheck disable=SC1090
source "$ENV_FILE"
set +a

COMPOSE_ARGS=(--env-file "$ENV_FILE" -f docker-compose.yml -f docker-compose.prod.yml)
if [[ "${WITH_LLM:-0}" == "1" ]]; then
  COMPOSE_ARGS+=(-f docker-compose.llm.yml)
fi

POSTGRES_USER="${POSTGRES_USER:-isms}"
POSTGRES_DB="${POSTGRES_DB:-isms}"

echo "[restore] stopping application traffic"
docker compose "${COMPOSE_ARGS[@]}" stop reverse-proxy app

echo "[restore] restoring database $POSTGRES_DB"
docker compose "${COMPOSE_ARGS[@]}" exec -T db \
  dropdb -U "$POSTGRES_USER" --if-exists --force "$POSTGRES_DB"
docker compose "${COMPOSE_ARGS[@]}" exec -T db \
  createdb -U "$POSTGRES_USER" "$POSTGRES_DB"

gunzip -c "$RESTORE_DIR/postgres.sql.gz" | docker compose "${COMPOSE_ARGS[@]}" exec -T db \
  psql -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB"

echo "[restore] restoring media"
cat "$RESTORE_DIR/storage.tar.gz" | docker compose "${COMPOSE_ARGS[@]}" run --rm --entrypoint sh app \
  -lc 'mkdir -p /app/media && find /app/media -mindepth 1 -maxdepth 1 -exec rm -rf -- {} + && tar -C /app -xzf -'

echo "[restore] starting application services"
docker compose "${COMPOSE_ARGS[@]}" up -d db app reverse-proxy

echo "[restore] done"
