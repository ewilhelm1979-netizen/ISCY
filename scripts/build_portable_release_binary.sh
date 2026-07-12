#!/usr/bin/env bash
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

output_dir="${1:-artifacts/portable-release}"
container_engine="${ISCY_CONTAINER_ENGINE:-docker}"

case "$output_dir" in
    artifacts/*) ;;
    *)
        echo 'PORTABLE_BUILD_ERROR[output_path]: Ausgabe muss relativ unter artifacts/ liegen.' >&2
        exit 1
        ;;
esac
if [[ "$output_dir" == *'/../'* || "$output_dir" == '../'* || "$output_dir" == *'/..' ]]; then
    echo 'PORTABLE_BUILD_ERROR[output_path]: Parent-Traversal ist nicht erlaubt.' >&2
    exit 1
fi
command -v "$container_engine" >/dev/null 2>&1 \
    || { echo 'PORTABLE_BUILD_ERROR[prerequisite]: Container-Engine fehlt.' >&2; exit 1; }

source_date_epoch="$(git show -s --format=%ct HEAD)"
mkdir -p "$repo_root/artifacts"
tmp_dir="$(mktemp -d "$repo_root/artifacts/.portable-build.XXXXXX")"
auth_dir="$(mktemp -d "$repo_root/artifacts/.portable-auth.XXXXXX")"
cleanup() {
    rm -rf "$tmp_dir" "$auth_dir"
}
trap cleanup EXIT
printf '{"auths":{}}\n' >"$auth_dir/config.json"
printf '{}\n' >"$auth_dir/auth.json"

build_args=(
    build
    --file rust/iscy-backend/Dockerfile.release
    --platform linux/amd64
    --target artifact
    --build-arg "SOURCE_DATE_EPOCH=$source_date_epoch"
    --output "type=local,dest=$tmp_dir"
)
if [[ "${ISCY_RELEASE_BUILD_NO_CACHE:-0}" == "1" ]]; then
    build_args+=(--no-cache)
fi
build_args+=(.)

DOCKER_BUILDKIT=1 \
DOCKER_CONFIG="$auth_dir" \
REGISTRY_AUTH_FILE="$auth_dir/auth.json" \
    "$container_engine" "${build_args[@]}"
[[ -f "$tmp_dir/iscy-backend" && -x "$tmp_dir/iscy-backend" ]] \
    || { echo 'PORTABLE_BUILD_ERROR[binary]: Exportiertes Binary fehlt oder ist nicht ausfuehrbar.' >&2; exit 1; }

rm -rf "$output_dir"
mkdir -p "$output_dir"
install -m 0755 "$tmp_dir/iscy-backend" "$output_dir/iscy-backend"

echo "PORTABLE_BUILD_OK: linux-x86_64-glibc Binary unter $output_dir erzeugt."
