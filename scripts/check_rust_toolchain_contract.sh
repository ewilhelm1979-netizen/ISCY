#!/usr/bin/env bash
set -euo pipefail

# This is a local consistency contract, not an image-authenticity oracle. The
# reviewed manifest supplies the digest; provenance is verified separately.
fail() {
    printf 'RC_METADATA_ERROR[toolchain]: %s\n' "$1" >&2
    exit 1
}

repo_root="$(git rev-parse --show-toplevel)" \
    || fail 'Git-Pruefkontext fehlt.'
cd "$repo_root"

manifest="${ISCY_RELEASE_MANIFEST_PATH:-release/release-manifest.json}"
ci='.github/workflows/ci.yml'
package='rust/iscy-backend/Cargo.toml'
product_dockerfile='rust/iscy-backend/Dockerfile'
release_dockerfile='rust/iscy-backend/Dockerfile.release'
builder_version='1.98.1'
msrv_version='1.88.0'
nix_version='1.95.0'

command -v jq >/dev/null 2>&1 || fail 'jq ist erforderlich.'
command -v awk >/dev/null 2>&1 || fail 'awk ist erforderlich.'

for path in "$manifest" "$ci" "$package" "$product_dockerfile" "$release_dockerfile"; do
    [[ -f "$path" && ! -L "$path" ]] \
        || fail 'Eine erforderliche Toolchain-Vertragsdatei fehlt oder ist ein Symlink.'
done

jq -e \
    --arg builder "$builder_version" \
    --arg nix "$nix_version" '
    .rust_version.package_msrv == "1.88"
    and .rust_version.ci_product_builder == $builder
    and .rust_version.product_container_builder == $builder
    and .rust_version.portable_release_builder == $builder
    and .rust_version.nix_development_path == $nix
    and (.release_artifact.builder_image | type == "string")
' "$manifest" >/dev/null 2>&1 \
    || fail 'Manifest muss Produkt-, CI- und Release-Rust 1.98.1, MSRV 1.88 und Nix-Rust 1.95.0 trennen.'

builder_image="$(jq -er '.release_artifact.builder_image' "$manifest")" \
    || fail 'Builder-Image fehlt im Manifest.'
[[ "$builder_image" =~ ^docker\.io/library/rust:1\.98\.1-bookworm@sha256:[0-9a-f]{64}$ ]] \
    || fail 'Manifest-Builder muss Rust 1.98.1-bookworm mit vollstaendigem SHA-256-Digest pinnen.'

# Parse only the explicit, reviewed workflow form. Dynamic/inline/matrix pins,
# duplicate inputs and additional toolchain consumers require contract review;
# they must not silently inherit the preceding job's policy.
ci_records="$(awk '
    /^[[:space:]]*#/ { next }
    /^jobs:[[:space:]]*$/ {
        in_jobs = 1
        print "section\tjobs"
        next
    }
    /^[^[:space:]]/ { in_jobs = 0 }
    !in_jobs { next }
    /^  [A-Za-z_][A-Za-z0-9_-]*:[[:space:]]*$/ {
        job = $0
        sub(/^  /, "", job)
        sub(/:[[:space:]]*$/, "", job)
        rust_step = 0
        rust_with = 0
        print "job\t" job
        next
    }
    /^      - / { rust_step = 0; rust_with = 0 }
    /uses:[[:space:]]*dtolnay\/rust-toolchain@/ {
        if ($0 !~ /^      - uses:[[:space:]]*dtolnay\/rust-toolchain@/) {
            print "invalid\t" job
            next
        }
        rust_step = 1
        print "action\t" job
        next
    }
    /^        with:[[:space:]]*$/ {
        if (rust_step) rust_with = 1
        next
    }
    /^[[:space:]]*toolchain[[:space:]]*:/ {
        if (!rust_step || !rust_with || $0 !~ /^          toolchain[[:space:]]*:/) {
            print "invalid\t" job
            next
        }
        value = $0
        sub(/^[[:space:]]*toolchain[[:space:]]*:[[:space:]]*/, "", value)
        sub(/[[:space:]]+#.*$/, "", value)
        sub(/[[:space:]]*$/, "", value)
        print "toolchain\t" job "\t" value
    }
' "$ci")" || fail 'CI-Toolchain-Vertrag ist nicht lesbar.'

declare -A expected_ci=(
    [rust-backend-tests]="$builder_version"
    [rust-bootstrap-smoke]="$builder_version"
    [object-storage-integration]="$builder_version"
    [rust-msrv-1-88]="$msrv_version"
)
declare -A seen_jobs=()
declare -A seen_actions=()
declare -A seen_toolchains=()
ci_section_count=0

while IFS=$'\t' read -r kind job value; do
    [[ -n "$kind" && -n "$job" ]] || fail 'CI-Toolchain ohne eindeutigen Jobkontext.'
    case "$kind" in
        section) ci_section_count=$((ci_section_count + 1)) ;;
        job)
            [[ -z "${seen_jobs[$job]:-}" ]] || fail 'Doppelter CI-Job im Toolchain-Vertrag.'
            seen_jobs["$job"]=1
            ;;
        action)
            [[ -n "${expected_ci[$job]:-}" ]] || fail 'Unerwarteter CI-Job installiert eine Rust-Toolchain.'
            [[ -z "${seen_actions[$job]:-}" ]] || fail 'Mehrere Rust-Toolchain-Aktionen in einem CI-Job.'
            seen_actions["$job"]=1
            ;;
        toolchain)
            [[ -n "${expected_ci[$job]:-}" ]] || fail 'Unerwarteter CI-Job setzt eine Rust-Toolchain.'
            [[ -z "${seen_toolchains[$job]:-}" ]] || fail 'Doppelter CI-Toolchain-Pin.'
            [[ "$value" == "${expected_ci[$job]}" ]] || fail 'CI-Toolchain weicht vom Produkt-/MSRV-Vertrag ab.'
            seen_toolchains["$job"]=1
            ;;
        *) fail 'Unerwartete CI-Toolchain-Struktur.' ;;
    esac
done <<<"$ci_records"
[[ "$ci_section_count" == 1 ]] || fail 'CI-Jobs-Abschnitt fehlt oder ist mehrdeutig.'

for job in "${!expected_ci[@]}"; do
    [[ "${seen_jobs[$job]:-}" == 1 \
        && "${seen_actions[$job]:-}" == 1 \
        && "${seen_toolchains[$job]:-}" == 1 ]] \
        || fail 'Ein verpflichtender expliziter CI-Toolchain-Pin fehlt.'
done

package_records="$(awk '
    /^[[:space:]]*#/ { next }
    /^[[:space:]]*\[package\][[:space:]]*$/ {
        in_package = 1
        print "package"
        next
    }
    /^[[:space:]]*\[/ { in_package = 0 }
    in_package && /^[[:space:]]*rust-version[[:space:]]*=/ {
        value = $0
        sub(/^[[:space:]]*rust-version[[:space:]]*=[[:space:]]*/, "", value)
        sub(/[[:space:]]+#.*$/, "", value)
        sub(/[[:space:]]*$/, "", value)
        print "msrv\t" value
    }
' "$package")" || fail 'Cargo-Paketvertrag ist nicht lesbar.'

package_count=0
package_msrv_count=0
while IFS=$'\t' read -r kind value; do
    case "$kind" in
        package) package_count=$((package_count + 1)) ;;
        msrv)
            package_msrv_count=$((package_msrv_count + 1))
            [[ "$value" == '"1.88"' || "$value" == '"1.88.0"' ]] \
                || fail 'Cargo-Paket-MSRV muss explizit Rust 1.88 bleiben.'
            ;;
        *) fail 'Unerwartete Cargo-MSRV-Struktur.' ;;
    esac
done <<<"$package_records"
[[ "$package_count" == 1 && "$package_msrv_count" == 1 ]] \
    || fail 'Cargo-Paket-MSRV fehlt oder ist mehrdeutig.'

# Compare the complete active builder stages, rather than just searching for
# a version somewhere in the file. This also rejects an extra unguarded build,
# a duplicated/bypassed rustc guard, an unlocked build, or weakened source and
# reproducibility inputs. Runtime-stage policy remains in the existing gates.
# Blank lines and whole-line comments are immaterial; other stage edits need
# an explicit update to this narrow contract and its regression fixtures.
stage_headers() {
    awk '/^[[:space:]]*[Ff][Rr][Oo][Mm][[:space:]]/ { sub(/[[:space:]]+$/, ""); print }' "$1"
}
[[ "$(stage_headers "$product_dockerfile")" == "$(printf '%s\n' "FROM $builder_image AS builder" 'FROM debian:bookworm-slim')" ]] \
    || fail 'Produkt-Stage-Struktur fehlt, ist mehrdeutig oder schattet den geprueften Builder ab.'
[[ "$(stage_headers "$release_dockerfile")" == "$(printf '%s\n' "FROM --platform=linux/amd64 $builder_image AS builder" 'FROM scratch AS artifact')" ]] \
    || fail 'Release-Stage-Struktur fehlt, ist mehrdeutig oder schattet den geprueften Builder ab.'

builder_stage() {
    awk '
        /^[[:space:]]*#[[:space:]]*(syntax|escape)[[:space:]]*=/ { exit 1 }
        /^[[:space:]]*(#|$)/ { next }
        /^[[:space:]]*[Ff][Rr][Oo][Mm][[:space:]]/ {
            stages++
            if (stages == 2) exit
        }
        { sub(/[[:space:]]+$/, ""); print }
    ' "$1"
}

printf -v version_guard "test \"\$(rustc --version | cut -d ' ' -f 2)\" = \"%s\"" "$builder_version"
expected_product_stage="$(printf '%s\n' \
    "FROM $builder_image AS builder" \
    'WORKDIR /build/rust/iscy-backend' \
    'COPY rust/iscy-backend/Cargo.toml rust/iscy-backend/Cargo.lock ./' \
    'COPY rust/iscy-backend/src ./src' \
    'COPY rust/iscy-backend/seeds ./seeds' \
    'COPY deploy /build/deploy' \
    'COPY flake.lock /build/flake.lock' \
    "RUN $version_guard \\" \
    '    && cargo build --release --locked')"
actual_product_stage="$(builder_stage "$product_dockerfile")" \
    || fail 'Produkt-Builder-Stage ist nicht lesbar.'
[[ "$actual_product_stage" == "$expected_product_stage" ]] \
    || fail 'Produkt-Builder verletzt Image-, Versionsguard-, Lockfile- oder Source-Vertrag.'

expected_release_stage="$(printf '%s\n' \
    "FROM --platform=linux/amd64 $builder_image AS builder" \
    'ARG SOURCE_DATE_EPOCH' \
    'WORKDIR /usr/src/iscy/rust/iscy-backend' \
    "ENV CARGO_INCREMENTAL=0 \\" \
    "    CARGO_PROFILE_RELEASE_DEBUG=0 \\" \
    "    CARGO_PROFILE_RELEASE_STRIP=symbols \\" \
    '    RUSTFLAGS="--remap-path-prefix=/usr/local/cargo/registry=/usr/src/cargo-registry --remap-path-prefix=/usr/local/cargo/git=/usr/src/cargo-git"' \
    'COPY rust/iscy-backend/Cargo.toml rust/iscy-backend/Cargo.lock ./' \
    'COPY rust/iscy-backend/src ./src' \
    'COPY rust/iscy-backend/seeds ./seeds' \
    'COPY deploy /usr/src/iscy/deploy' \
    'COPY flake.lock /usr/src/iscy/flake.lock' \
    "RUN test -n \"\$SOURCE_DATE_EPOCH\" \\" \
    "    && case \"\$SOURCE_DATE_EPOCH\" in *[!0-9]*) exit 1 ;; esac \\" \
    "    && $version_guard \\" \
    "    && SOURCE_DATE_EPOCH=\"\$SOURCE_DATE_EPOCH\" \\" \
    '       cargo build --release --locked --bin iscy-backend')"
actual_release_stage="$(builder_stage "$release_dockerfile")" \
    || fail 'Release-Builder-Stage ist nicht lesbar.'
[[ "$actual_release_stage" == "$expected_release_stage" ]] \
    || fail 'Release-Builder verletzt Image-, Plattform-, Versionsguard-, Lockfile- oder Reproduzierbarkeitsvertrag.'

actual_artifact_stage="$(awk '
    /^[[:space:]]*(#|$)/ { next }
    /^[[:space:]]*[Ff][Rr][Oo][Mm][[:space:]]/ { stages++ }
    stages == 2 { sub(/[[:space:]]+$/, ""); print }
' "$release_dockerfile")"
[[ "$actual_artifact_stage" == "$(printf '%s\n' 'FROM scratch AS artifact' 'COPY --from=builder /usr/src/iscy/rust/iscy-backend/target/release/iscy-backend /iscy-backend')" ]] \
    || fail 'Release-Artefakt stammt nicht ausschliesslich aus dem geprueften Builder.'

printf 'Rust-Toolchain-Vertrag OK (Produkt/CI/Release %s; MSRV 1.88; Nix %s).\n' \
    "$builder_version" "$nix_version"
