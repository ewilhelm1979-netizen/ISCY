#!/usr/bin/env bash
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

source_notes='docs/RELEASE_NOTES_DRAFT.md'
source_manifest='release/release-manifest.json'
guard='./scripts/check_release_notes_completeness.sh'
tmp_dir="$(mktemp -d)"
cleanup() {
    rm -rf "$tmp_dir"
}
trap cleanup EXIT

candidate_manifest="$tmp_dir/candidate-manifest.json"
jq '
    .release_status = "prepared_not_published"
    | .test_suite_summary.status = "validated_by_release_candidate_check_and_ci"
    | .release_artifact.reproducibility_status = "required_two_build_sha256"
' "$source_manifest" >"$candidate_manifest"

candidate_notes="$tmp_dir/candidate-notes.md"
cat >"$candidate_notes" <<'EOF'
# ISCY V23.7.30 - Release Notes

Status: Stabiler Release vorbereitet; Tag und GitHub Release noch nicht erstellt.

Vorgänger: `V23.7.29`.

nginx:1.31-alpine, Rust `1.97.0`, MSRV bleibt Rust `1.88.0` und nixos-26.05
bleiben die geprueften Plattformgrenzen. PostgreSQL 16 bleibt der Standard;
PostgreSQL 18.4 bleibt der zusaetzliche Kompatibilitaetspfad.

Der NIS2-Relevanz-Wizard dokumentiert eine Applicability-Begruendung im
NIS2- und KRITIS-Kontext, liefert aber keine rechtsverbindliche Einstufung.
Eine DORA-Konformitaetsbewertung erfolgt nicht. Fuer den Cyber Resilience Act
(CRA) gibt es keine automatische Konformitaetsbewertung oder CE-Freigabe.
ISCY liefert keine automatische Zertifizierung und keine Rechtsberatung.
EOF

expect_rejected() {
    local label="$1"
    local manifest="$2"
    local notes="$3"
    local expected_category="$4"
    local output

    if output="$(ISCY_RELEASE_MANIFEST_PATH="$manifest" "$guard" "$notes" 2>&1)"; then
        printf 'RELEASE_NOTES_TEST_ERROR[%s]: Widerspruechliche Notes wurden akzeptiert.\n' "$label" >&2
        exit 1
    fi
    [[ "$output" == *"RC_NOTES_ERROR[$expected_category]"* ]] || {
        printf 'RELEASE_NOTES_TEST_ERROR[%s]: Unerwartete Fehlerklasse.\n' "$label" >&2
        exit 1
    }
}

ISCY_RELEASE_MANIFEST_PATH="$source_manifest" "$guard" "$source_notes" >/dev/null

wrong_development_version="$tmp_dir/wrong-development-version.md"
sed 's/ISCY V23\.7\.30/ISCY V23.7.31/' "$source_notes" >"$wrong_development_version"
expect_rejected wrong_development_version "$source_manifest" "$wrong_development_version" target_version

development_published="$tmp_dir/development-published.md"
cp "$source_notes" "$development_published"
printf '\nStable Release veroeffentlicht.\n' >>"$development_published"
expect_rejected development_published "$source_manifest" "$development_published" stable_published

ISCY_RELEASE_MANIFEST_PATH="$candidate_manifest" "$guard" "$candidate_notes" >/dev/null

candidate_missing_regulatory="$tmp_dir/candidate-missing-regulatory.md"
sed 's/NIS2-Relevanz-Wizard/NIS2-Arbeitsablauf/' "$candidate_notes" >"$candidate_missing_regulatory"
expect_rejected candidate_missing_regulatory "$candidate_manifest" "$candidate_missing_regulatory" nis2_wizard

candidate_with_development_placeholder="$tmp_dir/candidate-development-placeholder.md"
cp "$candidate_notes" "$candidate_with_development_placeholder"
printf '\nStatus: Development / Unreleased. Aenderungen werden unter Unreleased dokumentiert.\n' \
    >>"$candidate_with_development_placeholder"
expect_rejected candidate_development_placeholder "$candidate_manifest" "$candidate_with_development_placeholder" development_status

echo 'Release-Notes-Modustests OK'
