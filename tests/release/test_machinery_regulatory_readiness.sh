#!/usr/bin/env bash
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

fail() {
    printf 'MACHINERY_READINESS_TEST_ERROR[%s]: %s\n' "$1" "$2" >&2
    exit 1
}

stale_day='14'
stale_iso="$(printf '2027-01-%s' "$stale_day")"
stale_german="$(printf '%s. Januar 2027' "$stale_day")"
stale_english="$(printf '%s January 2027' "$stale_day")"
stale_pattern="${stale_iso}|${stale_german}|${stale_english}"

if git grep -n -I -E -i "$stale_pattern" -- . ':!docs/ISCY_Handbuch.pdf'; then
    fail application_date 'Veralteter allgemeiner Anwendungstermin gefunden.'
fi
if grep -aE -i -q "$stale_pattern" docs/ISCY_Handbuch.pdf; then
    fail application_date 'Das generierte Handbuch-PDF enthaelt den veralteten Anwendungstermin.'
fi

grep -Fq '20. Januar 2027' docs/MACHINERY_CRA_SAFETY_SECURITY.md \
    || fail application_date 'Der korrigierte allgemeine Anwendungstermin fehlt.'
grep -Fq '20. Januar 2027' docs/ISCY_Handbuch.md \
    || fail application_date 'Der korrigierte Anwendungstermin fehlt im Handbuch-Quelltext.'
grep -aFq '20. Januar 2027' docs/ISCY_Handbuch.pdf \
    || fail generated_handbook 'Das Handbuch-PDF wurde nicht aus dem korrigierten Quelltext erzeugt.'
grep -Fq '/corrigendum/2023-07-04/oj/eng' docs/MACHINERY_CRA_SAFETY_SECURITY.md \
    || fail official_source 'Die offizielle EUR-Lex-Korrigendum-Quelle fehlt.'

echo 'Machinery-Regulatory-Date- und Readiness-Vertrag OK'
