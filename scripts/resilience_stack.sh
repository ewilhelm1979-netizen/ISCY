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

case "${1:-}" in
  up)
    compose up --build --detach
    wait_ready "http://127.0.0.1:19101" "Backend A"
    wait_ready "http://127.0.0.1:19102" "Backend B"
    wait_ready "http://127.0.0.1:19100" "HA-Proxy"
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
