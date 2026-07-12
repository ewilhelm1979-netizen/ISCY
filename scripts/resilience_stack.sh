#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_FILE="$ROOT_DIR/tests/resilience/docker-compose.ha.yml"
PROJECT_NAME="${ISCY_RESILIENCE_PROJECT:-iscy-resilience}"

if [[ ! "$PROJECT_NAME" =~ ^[a-z0-9][a-z0-9_-]{0,40}$ ]]; then
  echo "Ungueltiger Resilience-Compose-Projektname." >&2
  exit 2
fi

compose() {
  docker compose --project-name "$PROJECT_NAME" --file "$COMPOSE_FILE" "$@"
}

wait_ready() {
  local url="$1"
  local label="$2"
  for _ in $(seq 1 90); do
    if curl --fail --silent --show-error "$url/health/ready" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  echo "$label wurde nicht rechtzeitig betriebsbereit." >&2
  return 1
}

sync_test_sequences() {
  local synchronized_id
  synchronized_id="$(compose exec -T postgres psql \
    --username iscy_test --dbname iscy_test --tuples-only --no-align \
    --set=ON_ERROR_STOP=1 --command "
      WITH evidence_sequence AS (
        SELECT pg_get_serial_sequence('evidence_evidenceitem', 'id') AS sequence_name,
               GREATEST(COALESCE(MAX(id), 1), 1) AS maximum_id
        FROM evidence_evidenceitem
      )
      SELECT setval(sequence_name, maximum_id, TRUE)
      FROM evidence_sequence;
    ")"
  if [[ ! "$synchronized_id" =~ ^[0-9]+$ ]]; then
    echo "Evidence-Testsequence konnte nicht sicher synchronisiert werden." >&2
    return 1
  fi
}

case "${1:-}" in
  up)
    compose up --build --detach
    wait_ready "http://127.0.0.1:19101" "Backend A"
    wait_ready "http://127.0.0.1:19102" "Backend B"
    wait_ready "http://127.0.0.1:19100" "HA-Proxy"
    sync_test_sequences
    ;;
  down)
    compose down --volumes --remove-orphans
    ;;
  wait)
    wait_ready "${2:?URL fehlt}" "${3:-Dienst}"
    ;;
  compose)
    shift
    compose "$@"
    ;;
  *)
    echo "Usage: $0 {up|down|wait URL [LABEL]|compose ...}" >&2
    exit 2
    ;;
esac
