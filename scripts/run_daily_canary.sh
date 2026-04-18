#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$PROJECT_DIR"

: "${RUST_BACKEND_URL:?RUST_BACKEND_URL muss gesetzt sein}"
: "${CANARY_CVES_FILE:=scripts/canary_cves.txt}"
: "${CANARY_REPORTS_DIR:=reports/canary}"
: "${CANARY_WINDOW:=30}"
: "${CANARY_MAX_MISMATCH_RATE:=0.5}"

if [ ! -f "$CANARY_CVES_FILE" ]; then
  echo "[ERR] CVE-Datei fehlt: $CANARY_CVES_FILE" >&2
  exit 1
fi

mapfile -t CVES < <(grep -E '^[[:space:]]*CVE-[0-9]{4}-[0-9]+' "$CANARY_CVES_FILE" | tr -d '[:space:]')
if [ "${#CVES[@]}" -eq 0 ]; then
  echo "[ERR] Keine gueltigen CVE-IDs in $CANARY_CVES_FILE gefunden." >&2
  exit 1
fi

if command -v iscy-canary >/dev/null 2>&1; then
  ISCY_CANARY_BIN="iscy-canary"
else
  ISCY_CANARY_BIN="cargo run --manifest-path rust/iscy-backend/Cargo.toml --bin iscy-canary --"
fi

# shellcheck disable=SC2086
$ISCY_CANARY_BIN parity --out-dir "$CANARY_REPORTS_DIR" "${CVES[@]}"
# shellcheck disable=SC2086
$ISCY_CANARY_BIN trend \
  --reports-dir "$CANARY_REPORTS_DIR" \
  --window "$CANARY_WINDOW" \
  --max-mismatch-rate "$CANARY_MAX_MISMATCH_RATE" \
  --enforce-gate

echo "[OK] Daily Canary abgeschlossen."
