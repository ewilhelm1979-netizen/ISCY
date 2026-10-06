#!/usr/bin/env bash
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

guard='./scripts/check_rust_advisory_reachability.sh'
tmp_dir="$(mktemp -d)"
cleanup() {
    rm -rf "$tmp_dir"
}
trap cleanup EXIT

mkdir -p "$tmp_dir/bin"
fake_cargo="$tmp_dir/bin/cargo"
cat >"$fake_cargo" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

[[ "$*" == *'tree --locked'* \
    && "$*" == *'--manifest-path rust/iscy-backend/Cargo.toml'* \
    && "$*" == *'--target all'* \
    && "$*" == *'--edges normal,build,dev'* \
    && "$*" == *'--prefix none'* ]] || exit 64

case "${ISCY_TEST_DEPENDENCY_GRAPH:-safe}" in
    safe)
        printf '%s\n' 'iscy-backend v0.3.22' 'rust_decimal v1.42.1'
        ;;
    rkyv)
        printf '%s\n' 'iscy-backend v0.3.22' 'rkyv v0.7.46 (*)'
        ;;
    rsa)
        printf '%s\n' 'iscy-backend v0.3.22' 'rsa v0.9.8'
        ;;
    failure)
        exit 42
        ;;
    *)
        exit 65
        ;;
esac
EOF
chmod +x "$fake_cargo"

run_guard() {
    PATH="$tmp_dir/bin:$PATH" \
        ISCY_TEST_DEPENDENCY_GRAPH="$1" \
        "$guard"
}

expect_rejected() {
    local fixture="$1"
    local expected_category="$2"
    local output

    if output="$(run_guard "$fixture" 2>&1)"; then
        printf 'RUST_ADVISORY_REACHABILITY_TEST_ERROR[%s]: Unsicherer Graph wurde akzeptiert.\n' \
            "$fixture" >&2
        exit 1
    fi
    [[ "$output" == *"RUST_ADVISORY_REACHABILITY_ERROR[$expected_category]"* ]] || {
        printf 'RUST_ADVISORY_REACHABILITY_TEST_ERROR[%s]: Unerwartete Fehlerklasse.\n' \
            "$fixture" >&2
        exit 1
    }
}

run_guard safe >/dev/null
expect_rejected rkyv active_dependency
expect_rejected rsa active_dependency
expect_rejected failure dependency_graph

grep -Fq './scripts/check_rust_advisory_reachability.sh' .github/workflows/ci.yml \
    || {
        echo 'RUST_ADVISORY_REACHABILITY_TEST_ERROR[ci]: CI verwendet den gemeinsamen Guard nicht.' >&2
        exit 1
    }
grep -Fq './scripts/check_rust_advisory_reachability.sh' scripts/run_release_candidate_check.sh \
    || {
        echo 'RUST_ADVISORY_REACHABILITY_TEST_ERROR[release]: Der lokale Release-Check verwendet den gemeinsamen Guard nicht.' >&2
        exit 1
    }

echo 'Rust-Advisory-Reachability-Regressionstests OK'
