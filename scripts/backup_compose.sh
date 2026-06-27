#!/usr/bin/env bash
set -euo pipefail
umask 077

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

ENV_FILE="${ENV_FILE:-.env.production}"
BACKUP_DIR="${BACKUP_DIR:-$ROOT_DIR/backups}"
STAMP="$(date -u +%Y%m%d-%H%M%SZ)"
TARGET_DIR="$BACKUP_DIR/$STAMP"

if [[ ! -f "$ENV_FILE" ]]; then
  printf '[backup] environment file not found: %s\n' "$ENV_FILE" >&2
  exit 1
fi

set -a
# The operator-controlled production env file is intentionally loaded only for
# the backup process. It is never copied into the backup set.
# shellcheck disable=SC1090
source "$ENV_FILE"
set +a

mkdir -p "$TARGET_DIR"
chmod 700 "$TARGET_DIR"

COMPOSE_ARGS=(--env-file "$ENV_FILE" -f docker-compose.yml -f docker-compose.prod.yml)
if [[ "${WITH_LLM:-0}" == "1" ]]; then
  COMPOSE_ARGS+=(-f docker-compose.llm.yml)
fi

POSTGRES_USER="${POSTGRES_USER:-isms}"
POSTGRES_DB="${POSTGRES_DB:-isms}"

printf '[backup] writing into %s\n' "$TARGET_DIR"

docker compose "${COMPOSE_ARGS[@]}" exec -T db \
  pg_dump -U "$POSTGRES_USER" "$POSTGRES_DB" | gzip -c > "$TARGET_DIR/postgres.sql.gz"

docker compose "${COMPOSE_ARGS[@]}" run --rm --entrypoint sh app \
  -lc 'test -d /app/media && tar -C /app -czf - media' \
  > "$TARGET_DIR/storage.tar.gz"

test -s "$TARGET_DIR/postgres.sql.gz"
test -s "$TARGET_DIR/storage.tar.gz"

cat > "$TARGET_DIR/manifest.txt" <<EOF
created_at_utc=$STAMP
postgres_database=$POSTGRES_DB
postgres_user=$POSTGRES_USER
includes=postgres.sql.gz,storage.tar.gz
environment_snapshot_included=false
EOF

(
  cd "$TARGET_DIR"
  sha256sum postgres.sql.gz storage.tar.gz manifest.txt > SHA256SUMS
)
chmod 600 "$TARGET_DIR"/*

printf '[backup] done: %s\n' "$TARGET_DIR"
printf '[backup] note: protect this directory with encrypted storage or an encrypted transfer channel.\n'
