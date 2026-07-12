#!/usr/bin/env bash
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

first_dir='artifacts/portable-reproducibility/build-1'
second_dir='artifacts/portable-reproducibility/build-2'
release_dir='artifacts/portable-release'

command -v jq >/dev/null 2>&1 \
    || { echo 'REPRODUCIBILITY_ERROR[prerequisite]: jq fehlt.' >&2; exit 1; }

ISCY_RELEASE_BUILD_NO_CACHE=1 ./scripts/build_portable_release_binary.sh "$first_dir"
ISCY_RELEASE_BUILD_NO_CACHE=1 ./scripts/build_portable_release_binary.sh "$second_dir"
./scripts/check_release_binary_hygiene.sh "$first_dir/iscy-backend"
./scripts/check_release_binary_hygiene.sh "$second_dir/iscy-backend"

first_sha="$(sha256sum "$first_dir/iscy-backend" | cut -d ' ' -f 1)"
second_sha="$(sha256sum "$second_dir/iscy-backend" | cut -d ' ' -f 1)"
[[ "$first_sha" == "$second_sha" ]] \
    || { echo 'REPRODUCIBILITY_ERROR[sha256]: Zwei saubere Builds sind nicht byteidentisch.' >&2; exit 1; }
cmp -s "$first_dir/iscy-backend" "$second_dir/iscy-backend" \
    || { echo 'REPRODUCIBILITY_ERROR[content]: Zwei saubere Builds unterscheiden sich.' >&2; exit 1; }

rm -rf "$release_dir"
mkdir -p "$release_dir"
install -m 0755 "$first_dir/iscy-backend" "$release_dir/iscy-backend"
source_commit="$(git rev-parse HEAD)"
jq -n \
    --arg status verified_two_build_sha256 \
    --arg source_commit "$source_commit" \
    --arg sha256 "$first_sha" \
    --arg target linux-x86_64-glibc \
    '{status: $status, source_commit: $source_commit, sha256: $sha256, target: $target, builds: 2}' \
    >"$release_dir/reproducibility.json"
./scripts/run_release_binary_portability.sh "$release_dir/iscy-backend"

printf 'REPRODUCIBILITY_OK: builds=2 sha256=%s target=linux-x86_64-glibc\n' "$first_sha"
