#!/usr/bin/env bash
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

fail() {
    printf 'RUST_ADVISORY_REACHABILITY_ERROR[%s]: %s\n' "$1" "$2" >&2
    exit 1
}

command -v cargo >/dev/null 2>&1 \
    || fail prerequisite 'cargo fehlt.'
command -v grep >/dev/null 2>&1 \
    || fail prerequisite 'grep fehlt.'

manifest='rust/iscy-backend/Cargo.toml'
[[ -f "$manifest" && ! -L "$manifest" ]] \
    || fail manifest 'Das Rust-Manifest fehlt, ist kein regulaeres File oder ist ein Symlink.'

if ! active_dependency_tree="$(
    cargo tree --locked \
        --manifest-path "$manifest" \
        --target all \
        --edges normal,build,dev \
        --prefix none
)"; then
    fail dependency_graph 'Der aktive normal/build/dev-Dependency-Graph konnte nicht bestimmt werden.'
fi

if grep -Eq '^(rkyv|rsa) v[0-9]' <<<"$active_dependency_tree"; then
    printf '%s\n' "$active_dependency_tree" \
        | grep -E '^(rkyv|rsa) v[0-9]' >&2
    fail active_dependency 'Eine Advisory-Ausnahme ist im aktiven Dependency-Graph erreichbar.'
fi

echo 'RUST_ADVISORY_REACHABILITY_OK: rkyv und rsa sind im aktiven normal/build/dev-Graph aller Targets nicht erreichbar.'
