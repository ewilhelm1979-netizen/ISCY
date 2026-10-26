#!/usr/bin/env bash
set -euo pipefail
umask 077

repo_root="$(git rev-parse --show-toplevel)"
guard="${ISCY_RUST_TOOLCHAIN_GUARD_PATH:-$repo_root/scripts/check_rust_toolchain_contract.sh}"
[[ -f "$guard" && ! -L "$guard" ]] || {
    echo 'RUST_TOOLCHAIN_TEST_ERROR[fixture]: Toolchain-Guard fehlt.' >&2
    exit 1
}
# Fixture Git operations must never inherit an alternate real repository/index.
unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GIT_COMMON_DIR

tmp_dir="$(mktemp -d)"
cleanup() {
    rm -rf -- "$tmp_dir"
}
trap cleanup EXIT

seed="$tmp_dir/seed"
mkdir -p "$seed/.github/workflows" "$seed/rust/iscy-backend" "$seed/release" "$seed/scripts"
cp -- "$guard" "$seed/scripts/check_rust_toolchain_contract.sh"

# Deliberately construct an explicit synthetic 1.98.1 fixture. The caller's
# potentially broken PR files are never treated as the positive expectation.
# This all-a digest checks coherence/shape only, not registry authenticity.
fixture_digest='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
fixture_image="docker.io/library/rust:1.98.1-bookworm@sha256:$fixture_digest"
cat >"$seed/.github/workflows/ci.yml" <<'EOF'
name: Toolchain contract fixture
on: pull_request
jobs:
  rust-backend-tests:
    runs-on: ubuntu-24.04
    steps:
      - uses: dtolnay/rust-toolchain@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
        with:
          toolchain: 1.98.1
  rust-msrv-1-88:
    runs-on: ubuntu-24.04
    steps:
      - uses: dtolnay/rust-toolchain@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
        with:
          toolchain: 1.88.0
  rust-bootstrap-smoke:
    runs-on: ubuntu-24.04
    steps:
      - uses: dtolnay/rust-toolchain@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
        with:
          toolchain: 1.98.1
  object-storage-integration:
    runs-on: ubuntu-24.04
    steps:
      - uses: dtolnay/rust-toolchain@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
        with:
          toolchain: 1.98.1
EOF
cat >"$seed/rust/iscy-backend/Cargo.toml" <<'EOF'
[package]
name = "iscy-toolchain-fixture"
version = "0.0.0"
rust-version = "1.88"
EOF
cat >"$seed/rust/iscy-backend/Dockerfile" <<'EOF'
FROM FIXTURE_IMAGE AS builder
WORKDIR /build/rust/iscy-backend

COPY rust/iscy-backend/Cargo.toml rust/iscy-backend/Cargo.lock ./
COPY rust/iscy-backend/src ./src
COPY rust/iscy-backend/seeds ./seeds
COPY deploy /build/deploy
COPY flake.lock /build/flake.lock

RUN test "$(rustc --version | cut -d ' ' -f 2)" = "1.98.1" \
    && cargo build --release --locked

FROM debian:bookworm-slim
USER 10001:10001
EOF
cat >"$seed/rust/iscy-backend/Dockerfile.release" <<'EOF'
FROM --platform=linux/amd64 FIXTURE_IMAGE AS builder

ARG SOURCE_DATE_EPOCH
WORKDIR /usr/src/iscy/rust/iscy-backend

ENV CARGO_INCREMENTAL=0 \
    CARGO_PROFILE_RELEASE_DEBUG=0 \
    CARGO_PROFILE_RELEASE_STRIP=symbols \
    RUSTFLAGS="--remap-path-prefix=/usr/local/cargo/registry=/usr/src/cargo-registry --remap-path-prefix=/usr/local/cargo/git=/usr/src/cargo-git"

COPY rust/iscy-backend/Cargo.toml rust/iscy-backend/Cargo.lock ./
COPY rust/iscy-backend/src ./src
COPY rust/iscy-backend/seeds ./seeds
COPY deploy /usr/src/iscy/deploy
COPY flake.lock /usr/src/iscy/flake.lock

RUN test -n "$SOURCE_DATE_EPOCH" \
    && case "$SOURCE_DATE_EPOCH" in *[!0-9]*) exit 1 ;; esac \
    && test "$(rustc --version | cut -d ' ' -f 2)" = "1.98.1" \
    && SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" \
       cargo build --release --locked --bin iscy-backend

FROM scratch AS artifact
COPY --from=builder /usr/src/iscy/rust/iscy-backend/target/release/iscy-backend /iscy-backend
EOF
sed -i "s#FIXTURE_IMAGE#$fixture_image#g" \
    "$seed/rust/iscy-backend/Dockerfile" "$seed/rust/iscy-backend/Dockerfile.release"
jq -n --arg image "$fixture_image" '{
    rust_version: {
        package_msrv: "1.88",
        ci_product_builder: "1.98.1",
        product_container_builder: "1.98.1",
        portable_release_builder: "1.98.1",
        nix_development_path: "1.95.0"
    },
    release_artifact: {builder_image: $image}
}' >"$seed/release/release-manifest.json"

passed=0
rejected=0
new_case() {
    fixture="$tmp_dir/$1"
    fixture_manifest_override='release/release-manifest.json'
    mkdir -p "$fixture"
    cp -R -- "$seed/." "$fixture/"
    git init --quiet --initial-branch=fixture "$fixture"
}

run_guard() {
    (
        cd "$fixture"
        ISCY_RELEASE_MANIFEST_PATH="$fixture_manifest_override" \
            bash ./scripts/check_rust_toolchain_contract.sh
    )
}

expect_accepted() {
    local label="$1"
    local output
    if ! output="$(run_guard 2>&1)"; then
        printf 'RUST_TOOLCHAIN_TEST_ERROR[%s]: Koharenter Vertrag abgelehnt: %s\n' "$label" "$output" >&2
        exit 1
    fi
    passed=$((passed + 1))
}

expect_rejected() {
    local label="$1"
    local output
    if output="$(run_guard 2>&1)"; then
        printf 'RUST_TOOLCHAIN_TEST_ERROR[%s]: Widerspruechlicher Vertrag akzeptiert.\n' "$label" >&2
        exit 1
    fi
    [[ "$output" == *'RC_METADATA_ERROR[toolchain]'* ]] || {
        printf 'RUST_TOOLCHAIN_TEST_ERROR[%s]: Unerwartete Fehlerklasse: %s\n' "$label" "$output" >&2
        exit 1
    }
    rejected=$((rejected + 1))
}

mutate_manifest() {
    local filter="$1"
    jq "$filter" "$fixture/release/release-manifest.json" >"$fixture/manifest-next.json"
    mv -- "$fixture/manifest-next.json" "$fixture/release/release-manifest.json"
}

mutate_ci_pin() {
    local selected_job="$1"
    local replacement="$2"
    awk -v selected="$selected_job" -v replacement="$replacement" '
        /^  [A-Za-z_][A-Za-z0-9_-]*:/ {
            job = $0
            sub(/^  /, "", job)
            sub(/:.*/, "", job)
        }
        job == selected && /^[[:space:]]*toolchain:/ {
            sub(/toolchain:.*/, "toolchain: " replacement)
        }
        { print }
    ' "$fixture/.github/workflows/ci.yml" >"$fixture/ci-next.yml"
    mv -- "$fixture/ci-next.yml" "$fixture/.github/workflows/ci.yml"
}

new_case coherent_1981
expect_accepted coherent_1981

new_case cargo_msrv_full_patch
sed -i 's/rust-version = "1.88"/rust-version = "1.88.0"/' "$fixture/rust/iscy-backend/Cargo.toml"
expect_accepted cargo_msrv_full_patch

new_case docker_comments_and_blank_lines
sed -i '2i# Explicitly harmless whole-line comment' "$fixture/rust/iscy-backend/Dockerfile"
expect_accepted docker_comments_and_blank_lines

new_case original_pr_mismatch
sed -i 's/rust:1.98.1-bookworm/rust:1.98.0-bookworm/; /rustc --version/s/"1.98.1"/"1.97.0"/' \
    "$fixture/rust/iscy-backend/Dockerfile"
sed -i 's/rust:1.98.1-bookworm/rust:1.98-bookworm/; /rustc --version/s/"1.98.1"/"1.88.0"/' \
    "$fixture/rust/iscy-backend/Dockerfile.release"
expect_rejected original_pr_mismatch

for job in rust-backend-tests rust-bootstrap-smoke object-storage-integration; do
    new_case "wrong_ci_$job"
    mutate_ci_pin "$job" 1.97.0
    expect_rejected "wrong_ci_$job"
done

new_case wrong_ci_msrv
mutate_ci_pin rust-msrv-1-88 1.98.1
expect_rejected wrong_ci_msrv

new_case unexpected_toolchain_job
cat >>"$fixture/.github/workflows/ci.yml" <<'EOF'
  unexpected-rust-job:
    steps:
      - uses: dtolnay/rust-toolchain@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
        with:
          toolchain: 1.98.1
EOF
expect_rejected unexpected_toolchain_job

new_case missing_ci_pin
sed -i '0,/toolchain: 1.98.1/{/toolchain: 1.98.1/d;}' "$fixture/.github/workflows/ci.yml"
expect_rejected missing_ci_pin

new_case duplicate_ci_pin
sed -i '0,/toolchain: 1.98.1/s//toolchain: 1.98.1\n          toolchain: 1.98.1/' "$fixture/.github/workflows/ci.yml"
expect_rejected duplicate_ci_pin

new_case duplicate_ci_action
sed -i '0,/        with:/s//      - uses: dtolnay\/rust-toolchain@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n        with:/' "$fixture/.github/workflows/ci.yml"
expect_rejected duplicate_ci_action

new_case dynamic_ci_pin
mutate_ci_pin rust-backend-tests "\${{ matrix.rust }}"
expect_rejected dynamic_ci_pin

new_case missing_ci_action
sed -i '0,/dtolnay\/rust-toolchain@/s#dtolnay/rust-toolchain@#example/not-the-toolchain@#' "$fixture/.github/workflows/ci.yml"
expect_rejected missing_ci_action

new_case ci_pin_attached_to_wrong_action
sed -i '0,/        with:/s//      - uses: example\/unrelated@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n        with:/' "$fixture/.github/workflows/ci.yml"
expect_rejected ci_pin_attached_to_wrong_action

new_case duplicate_ci_job
cat >>"$fixture/.github/workflows/ci.yml" <<'EOF'
  rust-backend-tests:
    steps: []
EOF
expect_rejected duplicate_ci_job

new_case inline_ci_with
sed -i '0,/        with:/s//        with: { toolchain: 1.98.1 }/' "$fixture/.github/workflows/ci.yml"
expect_rejected inline_ci_with

for key in ci_product_builder product_container_builder portable_release_builder; do
    new_case "wrong_manifest_$key"
    mutate_manifest ".rust_version.$key = \"1.97.0\""
    expect_rejected "wrong_manifest_$key"
done

new_case wrong_manifest_msrv
mutate_manifest '.rust_version.package_msrv = "1.98.1"'
expect_rejected wrong_manifest_msrv

new_case wrong_manifest_nix
mutate_manifest '.rust_version.nix_development_path = "1.98.1"'
expect_rejected wrong_manifest_nix

new_case wrong_cargo_msrv
sed -i 's/rust-version = "1.88"/rust-version = "1.98.1"/' "$fixture/rust/iscy-backend/Cargo.toml"
expect_rejected wrong_cargo_msrv

new_case missing_cargo_msrv
sed -i '/^rust-version =/d' "$fixture/rust/iscy-backend/Cargo.toml"
expect_rejected missing_cargo_msrv

new_case duplicate_cargo_msrv
printf '%s\n' 'rust-version = "1.88"' >>"$fixture/rust/iscy-backend/Cargo.toml"
expect_rejected duplicate_cargo_msrv

for dockerfile in Dockerfile Dockerfile.release; do
    new_case "wrong_tag_$dockerfile"
    sed -i 's/rust:1.98.1-bookworm/rust:1.98.0-bookworm/' "$fixture/rust/iscy-backend/$dockerfile"
    expect_rejected "wrong_tag_$dockerfile"

    new_case "digest_drift_$dockerfile"
    sed -i "s/$fixture_digest/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb/" \
        "$fixture/rust/iscy-backend/$dockerfile"
    expect_rejected "digest_drift_$dockerfile"

    new_case "missing_guard_$dockerfile"
    sed -i '/rustc --version/d' "$fixture/rust/iscy-backend/$dockerfile"
    expect_rejected "missing_guard_$dockerfile"

    new_case "wrong_guard_$dockerfile"
    sed -i '/rustc --version/s/"1.98.1"/"1.97.0"/' "$fixture/rust/iscy-backend/$dockerfile"
    expect_rejected "wrong_guard_$dockerfile"

    new_case "duplicate_guard_$dockerfile"
    sed -i '/rustc --version/p' "$fixture/rust/iscy-backend/$dockerfile"
    expect_rejected "duplicate_guard_$dockerfile"

    new_case "unlocked_build_$dockerfile"
    sed -i 's/ --locked//' "$fixture/rust/iscy-backend/$dockerfile"
    expect_rejected "unlocked_build_$dockerfile"

    new_case "missing_lockfile_copy_$dockerfile"
    sed -i 's/Cargo.toml rust\/iscy-backend\/Cargo.lock/Cargo.toml/' "$fixture/rust/iscy-backend/$dockerfile"
    expect_rejected "missing_lockfile_copy_$dockerfile"

    new_case "unreviewed_parser_directive_$dockerfile"
    sed -i '1i# syntax=example/unreviewed-frontend:latest' "$fixture/rust/iscy-backend/$dockerfile"
    expect_rejected "unreviewed_parser_directive_$dockerfile"
done

new_case unpinned_manifest_builder
mutate_manifest '.release_artifact.builder_image = "docker.io/library/rust:1.98.1-bookworm"'
expect_rejected unpinned_manifest_builder

new_case truncated_manifest_digest
mutate_manifest '.release_artifact.builder_image |= sub("[a-f0-9]{64}$"; "abcd")'
expect_rejected truncated_manifest_digest

new_case wrong_manifest_builder_tag
mutate_manifest '.release_artifact.builder_image |= sub("1.98.1-bookworm"; "1.98.0-bookworm")'
expect_rejected wrong_manifest_builder_tag

new_case uppercase_manifest_digest
mutate_manifest '.release_artifact.builder_image |= sub("[a-f0-9]{64}$"; "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")'
expect_rejected uppercase_manifest_digest

new_case wrong_release_platform
sed -i 's/--platform=linux\/amd64/--platform=linux\/arm64/' "$fixture/rust/iscy-backend/Dockerfile.release"
expect_rejected wrong_release_platform

new_case missing_release_platform
sed -i 's/--platform=linux\/amd64 //' "$fixture/rust/iscy-backend/Dockerfile.release"
expect_rejected missing_release_platform

new_case missing_release_remapping
sed -i '/RUSTFLAGS=/d' "$fixture/rust/iscy-backend/Dockerfile.release"
expect_rejected missing_release_remapping

new_case missing_source_date_epoch_validation
sed -i '/case .*SOURCE_DATE_EPOCH/d' "$fixture/rust/iscy-backend/Dockerfile.release"
expect_rejected missing_source_date_epoch_validation

new_case extra_unguarded_product_build
sed -i '/^FROM debian:/iRUN cargo build --release' "$fixture/rust/iscy-backend/Dockerfile"
expect_rejected extra_unguarded_product_build

new_case shadow_product_builder_stage
sed -i '/^FROM debian:/iFROM docker.io/library/rust:1.97.0-bookworm AS builder' "$fixture/rust/iscy-backend/Dockerfile"
expect_rejected shadow_product_builder_stage

new_case shadow_release_builder_stage
sed -i '/^FROM scratch/iFROM docker.io/library/rust:1.88-bookworm AS builder' "$fixture/rust/iscy-backend/Dockerfile.release"
expect_rejected shadow_release_builder_stage

new_case wrong_artifact_builder
sed -i 's/COPY --from=builder/COPY --from=unreviewed/' "$fixture/rust/iscy-backend/Dockerfile.release"
expect_rejected wrong_artifact_builder

new_case wrong_artifact_path
sed -i 's# /iscy-backend$# /wrong-output#' "$fixture/rust/iscy-backend/Dockerfile.release"
expect_rejected wrong_artifact_path

new_case manifest_override_rejected
jq '.rust_version.portable_release_builder = "1.88"' \
    "$fixture/release/release-manifest.json" >"$fixture/override.json"
fixture_manifest_override="$fixture/override.json"
expect_rejected manifest_override_rejected

new_case manifest_override_accepted
cp -- "$fixture/release/release-manifest.json" "$fixture/override.json"
printf '%s\n' '{"broken_default":true}' >"$fixture/release/release-manifest.json"
fixture_manifest_override="$fixture/override.json"
expect_accepted manifest_override_accepted

printf 'Rust-Toolchain-Vertragstests OK (%s Positivfaelle, %s Negativfaelle).\n' "$passed" "$rejected"
