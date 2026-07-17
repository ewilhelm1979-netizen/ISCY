#!/usr/bin/env bash
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

require_command() {
    command -v "$1" >/dev/null 2>&1 || {
        printf 'RC_CHECK_ERROR[prerequisite]: %s fehlt.\n' "$1" >&2
        exit 1
    }
}

for command in cargo cargo-audit cargo-cyclonedx cargo-deny docker file jq ldd nix pg_dump pg_restore psql readelf sha256sum stat strings; do
    require_command "$command"
done

release_status="$(jq -er '.release_status | select(type == "string")' release/release-manifest.json)" || {
    echo 'RC_CHECK_ERROR[release_status]: Release-Status fehlt oder ist ungueltig.' >&2
    exit 1
}
case "$release_status" in
    development_unreleased)
        rm -rf artifacts/release-candidate
        ;;
    prepared_not_published) ;;
    *)
        echo 'RC_CHECK_ERROR[release_status]: Nicht unterstuetzter Root-Release-Status.' >&2
        exit 1
        ;;
esac

if [[ -z "${ISCY_POSTGRES_RESTORE_DRILL_SOURCE_URL:-}" \
    || -z "${ISCY_POSTGRES_RESTORE_DRILL_RESTORE_URL:-}" ]]; then
    echo 'RC_CHECK_ERROR[postgres_restore]: Zwei wegwerfbare PostgreSQL-Drill-URLs muessen gesetzt sein.' >&2
    exit 1
fi
if [[ "$ISCY_POSTGRES_RESTORE_DRILL_SOURCE_URL" == "$ISCY_POSTGRES_RESTORE_DRILL_RESTORE_URL" ]]; then
    echo 'RC_CHECK_ERROR[postgres_restore]: Source und Restore muessen getrennte Wegwerf-Datenbanken sein.' >&2
    exit 1
fi
if ! docker info >/dev/null 2>&1; then
    echo 'RC_CHECK_ERROR[docker_daemon]: Ein erreichbarer lokaler Docker-Daemon ist erforderlich.' >&2
    exit 1
fi
for database_url in \
    "$ISCY_POSTGRES_RESTORE_DRILL_SOURCE_URL" \
    "$ISCY_POSTGRES_RESTORE_DRILL_RESTORE_URL"; do
    if ! psql "$database_url" -Atc 'SELECT 1' >/dev/null 2>&1; then
        echo 'RC_CHECK_ERROR[postgres_restore]: Eine konfigurierte Wegwerf-Datenbank ist nicht erreichbar.' >&2
        exit 1
    fi
done

cargo fmt --manifest-path rust/iscy-backend/Cargo.toml -- --check
cargo clippy --locked --manifest-path rust/iscy-backend/Cargo.toml --all-targets -- -D warnings
cargo test --locked --manifest-path rust/iscy-backend/Cargo.toml
cargo audit --file rust/iscy-backend/Cargo.lock --ignore RUSTSEC-2023-0071
cargo deny --manifest-path rust/iscy-backend/Cargo.toml check advisories licenses sources

make rust-smoke
make rust-restore-smoke
make rust-postgres-restore-drill
make graceful-shutdown-smoke
make object-storage-integration
make performance-smoke
make ha-integration
./scripts/run_postgresql_18_compatibility_isolated.sh
make visual-regression
nix flake check
COMPOSE_ENV_FILE=.env.example make docker-check
docker build --file rust/iscy-backend/Dockerfile .
make docs-pdf
./scripts/handle_release_sbom_lifecycle.sh
make release-binary-gate
if [[ "$release_status" == 'prepared_not_published' ]]; then
    make release-candidate-artifacts
fi
make release-candidate-metadata-check

if [[ "$release_status" == 'development_unreleased' ]]; then
    [[ ! -e artifacts/release-candidate ]] || {
        echo 'RC_CHECK_ERROR[release_status]: Development-Gate hat unerwartet ein Release-Bundle hinterlassen.' >&2
        exit 1
    }
    echo 'DEV_CHECK_OK: vollstaendiger Entwicklungsstand geprueft; kein Release-Bundle erzeugt und nichts veroeffentlicht.'
else
    echo 'RC_CHECK_OK: vollstaendige lokale Release-Candidate-Pruefung erfolgreich; nichts veroeffentlicht.'
fi
