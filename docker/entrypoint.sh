#!/usr/bin/env bash
set -euo pipefail

cd /app

log() { printf '[entrypoint] %s\n' "$1"; }

wait_for_db() {
  python - <<'PY'
import os
import time
import sys
import dj_database_url
import psycopg

url = os.getenv('DATABASE_URL', '')
if not url or url.startswith('sqlite'):
    sys.exit(0)

cfg = dj_database_url.parse(url)
kwargs = {
    'dbname': cfg.get('NAME') or cfg.get('ENGINE', ''),
    'user': cfg.get('USER') or '',
    'password': cfg.get('PASSWORD') or '',
    'host': cfg.get('HOST') or 'db',
    'port': cfg.get('PORT') or 5432,
}
for attempt in range(1, 31):
    try:
        conn = psycopg.connect(**kwargs)
        conn.close()
        print('database-ready')
        sys.exit(0)
    except Exception as exc:
        print(f'database-wait attempt={attempt}: {exc}')
        time.sleep(2)
print('database-not-ready')
sys.exit(1)
PY
}

if [[ "${WAIT_FOR_DB:-1}" == "1" ]]; then
  log "waiting for database"
  wait_for_db
fi

if [[ "${RUN_MIGRATIONS:-1}" == "1" ]]; then
  log "running migrations"
  python manage.py migrate --noinput
fi

if [[ "${RUN_COLLECTSTATIC:-0}" == "1" ]]; then
  log "collecting static files"
  python manage.py collectstatic --noinput
fi

if [[ "${RUN_SEEDS:-0}" == "1" ]]; then
  log "running seed commands"
  python manage.py seed_demo || true
  python manage.py seed_catalog || true
  python manage.py seed_requirements || true
  python manage.py seed_product_security || true
fi

if [[ "${DJANGO_CHECK:-1}" == "1" ]]; then
  log "running django check"
  python manage.py check
fi

if [[ "${VERIFY_LOCAL_LLM:-0}" == "1" && "${LOCAL_LLM_ENABLED:-False}" == "True" ]]; then
  log "verifying local llm runtime"
  python manage.py check_local_llm || true
fi

if [[ $# -gt 0 ]]; then
  exec "$@"
fi

if [[ "${APP_SERVER:-gunicorn}" == "runserver" ]]; then
  exec python manage.py runserver 0.0.0.0:${PORT:-8000}
fi

exec gunicorn config.wsgi:application \
  --bind 0.0.0.0:${PORT:-8000} \
  --workers ${GUNICORN_WORKERS:-3} \
  --timeout ${GUNICORN_TIMEOUT:-120} \
  --access-logfile - \
  --error-logfile -
