#!/usr/bin/env bash
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

guard="$repo_root/scripts/handle_release_sbom_lifecycle.sh"
tmp_dir="$(mktemp -d)"
fake_bin="$tmp_dir/bin"
manifest="$tmp_dir/release-manifest.json"
sbom="$tmp_dir/iscy-backend.cdx.json"
make_log="$tmp_dir/make.log"
mkdir -p "$fake_bin"

cleanup() {
    rm -rf "$tmp_dir"
}
trap cleanup EXIT

cat >"$fake_bin/make" <<'EOF'
#!/usr/bin/env bash
set -eu
printf '%s\n' "$*" >>"$FAKE_MAKE_LOG"
exit "${FAKE_MAKE_EXIT:-0}"
EOF
chmod +x "$fake_bin/make"

write_valid_sbom() {
    jq -n '
        {
          bomFormat: "CycloneDX",
          specVersion: "1.5",
          version: 1,
          metadata: {component: {type: "application", name: "iscy-backend"}},
          components: [{type: "library", name: "example", version: "1.0.0"}],
          dependencies: [{ref: "iscy-backend", dependsOn: []}]
        }
    ' >"$sbom"
}

write_manifest() {
    local status="$1"
    local hash="$2"
    jq -n --arg status "$status" --arg hash "$hash" \
        '{release_status: $status, sbom_sha256: $hash}' >"$manifest"
}

run_guard() {
    PATH="$fake_bin:$PATH" \
    FAKE_MAKE_LOG="$make_log" \
    FAKE_MAKE_EXIT="${FAKE_MAKE_EXIT:-0}" \
    ISCY_RELEASE_MANIFEST_PATH="$manifest" \
    ISCY_RELEASE_SBOM_PATH="$sbom" \
        "$guard"
}

expect_failure() {
    local label="$1"
    local expected_category="$2"
    local output
    local status

    set +e
    output="$(run_guard 2>&1)"
    status=$?
    set -e
    [[ "$status" -ne 0 ]] || {
        printf 'RELEASE_SBOM_TEST_ERROR[%s]: Ungueltiger Lifecycle wurde akzeptiert.\n' "$label" >&2
        exit 1
    }
    [[ "$output" == *"RC_SBOM_ERROR[$expected_category]"* ]] || {
        printf 'RELEASE_SBOM_TEST_ERROR[%s]: Unerwartete Fehlerklasse.\n' "$label" >&2
        exit 1
    }
}

# Development: vorhandenen Snapshot validieren, ohne Datei oder Make-Aufruf.
write_valid_sbom
sbom_hash="$(sha256sum "$sbom" | cut -d ' ' -f 1)"
write_manifest development_unreleased "$sbom_hash"
touch -d '@1000000000' "$sbom"
cp "$sbom" "$tmp_dir/sbom-before.json"
mtime_before="$(stat -c '%y' "$sbom")"
hash_before="$(sha256sum "$sbom" | cut -d ' ' -f 1)"
files_before="$(find "$tmp_dir" -mindepth 1 -maxdepth 2 -type f -printf '%P\n' | sort)"
development_output="$(run_guard)"
files_after="$(find "$tmp_dir" -mindepth 1 -maxdepth 2 -type f -printf '%P\n' | sort)"
[[ "$development_output" == *'RC_SBOM_OK[development_snapshot]'* ]] || {
    echo 'RELEASE_SBOM_TEST_ERROR[development]: Erfolgsmeldung fehlt.' >&2
    exit 1
}
[[ ! -e "$make_log" ]] || {
    echo 'RELEASE_SBOM_TEST_ERROR[development]: make wurde aufgerufen.' >&2
    exit 1
}
cmp "$sbom" "$tmp_dir/sbom-before.json"
[[ "$(sha256sum "$sbom" | cut -d ' ' -f 1)" == "$hash_before" ]] || {
    echo 'RELEASE_SBOM_TEST_ERROR[development]: SBOM-Hash wurde veraendert.' >&2
    exit 1
}
[[ "$(stat -c '%y' "$sbom")" == "$mtime_before" ]] || {
    echo 'RELEASE_SBOM_TEST_ERROR[development]: SBOM-Mtime wurde veraendert.' >&2
    exit 1
}
[[ "$files_after" == "$files_before" ]] || {
    echo 'RELEASE_SBOM_TEST_ERROR[development]: Unerwartetes Artefakt wurde erzeugt.' >&2
    exit 1
}

# Development: Hashabweichung fail-closed.
write_valid_sbom
write_manifest development_unreleased "$(sha256sum "$sbom" | cut -d ' ' -f 1)"
printf ' ' >>"$sbom"
rm -f "$make_log"
expect_failure manifest_hash manifest_hash
[[ ! -e "$make_log" ]] || {
    echo 'RELEASE_SBOM_TEST_ERROR[manifest_hash]: make wurde aufgerufen.' >&2
    exit 1
}

# Development: ungueltige CycloneDX-Struktur ablehnen.
write_valid_sbom
jq '.bomFormat = "SPDX"' "$sbom" >"$tmp_dir/invalid-sbom.json"
mv "$tmp_dir/invalid-sbom.json" "$sbom"
write_manifest development_unreleased "$(sha256sum "$sbom" | cut -d ' ' -f 1)"
rm -f "$make_log"
expect_failure invalid_structure structure
[[ ! -e "$make_log" ]] || {
    echo 'RELEASE_SBOM_TEST_ERROR[invalid_structure]: make wurde aufgerufen.' >&2
    exit 1
}

# Development: lokale Buildpfade ablehnen, ohne sie auszugeben.
write_valid_sbom
jq '.metadata.component.name = "/home/test/build"' "$sbom" >"$tmp_dir/local-path-sbom.json"
mv "$tmp_dir/local-path-sbom.json" "$sbom"
write_manifest development_unreleased "$(sha256sum "$sbom" | cut -d ' ' -f 1)"
rm -f "$make_log"
expect_failure local_path local_path
[[ ! -e "$make_log" ]] || {
    echo 'RELEASE_SBOM_TEST_ERROR[local_path]: make wurde aufgerufen.' >&2
    exit 1
}

# Candidate: make release-sbom exakt einmal aufrufen.
write_valid_sbom
write_manifest prepared_not_published "$(sha256sum "$sbom" | cut -d ' ' -f 1)"
rm -f "$make_log"
run_guard
[[ "$(wc -l <"$make_log" | tr -d ' ')" == '1' ]] || {
    echo 'RELEASE_SBOM_TEST_ERROR[prepared]: make wurde nicht exakt einmal aufgerufen.' >&2
    exit 1
}
[[ "$(cat "$make_log")" == 'release-sbom' ]] || {
    echo 'RELEASE_SBOM_TEST_ERROR[prepared]: Unerwartete make-Argumente.' >&2
    exit 1
}

# Candidate: Exit-Code des Generators unveraendert propagieren.
rm -f "$make_log"
set +e
FAKE_MAKE_EXIT=23 run_guard >/dev/null 2>&1
prepared_status=$?
set -e
[[ "$prepared_status" -eq 23 ]] || {
    echo 'RELEASE_SBOM_TEST_ERROR[prepared_failure]: Exit-Code 23 wurde nicht propagiert.' >&2
    exit 1
}
[[ "$(wc -l <"$make_log" | tr -d ' ')" == '1' ]] || {
    echo 'RELEASE_SBOM_TEST_ERROR[prepared_failure]: make wurde nicht exakt einmal aufgerufen.' >&2
    exit 1
}

# Unbekannter Status: fail-closed ohne Make-Aufruf.
write_manifest stable_release_published "$(sha256sum "$sbom" | cut -d ' ' -f 1)"
rm -f "$make_log"
expect_failure unknown_status release_status
[[ ! -e "$make_log" ]] || {
    echo 'RELEASE_SBOM_TEST_ERROR[unknown_status]: make wurde aufgerufen.' >&2
    exit 1
}

# Development: fehlenden Manifesthash ablehnen.
write_manifest development_unreleased "$(sha256sum "$sbom" | cut -d ' ' -f 1)"
jq 'del(.sbom_sha256)' "$manifest" >"$tmp_dir/missing-hash-manifest.json"
mv "$tmp_dir/missing-hash-manifest.json" "$manifest"
rm -f "$make_log"
expect_failure missing_hash manifest_hash
[[ ! -e "$make_log" ]] || {
    echo 'RELEASE_SBOM_TEST_ERROR[missing_hash]: make wurde aufgerufen.' >&2
    exit 1
}

echo 'Release-SBOM-Lifecycle-Tests OK'
