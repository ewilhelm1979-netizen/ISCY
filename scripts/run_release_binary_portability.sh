#!/usr/bin/env bash
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

binary="${1:-artifacts/portable-release/iscy-backend}"
container_engine="${ISCY_CONTAINER_ENGINE:-docker}"
runtime_image='docker.io/library/debian:bookworm-slim@sha256:1def178129dfb5f24db43afbf2fcac04530012e3264ba4ff81c71184e17a9ee4'

fail() {
    printf 'PORTABILITY_ERROR[%s]: %s\n' "$1" "$2" >&2
    exit 1
}
command -v "$container_engine" >/dev/null 2>&1 || fail prerequisite 'Container-Engine fehlt.'
command -v curl >/dev/null 2>&1 || fail prerequisite 'curl fehlt.'
[[ -f "$binary" && -x "$binary" ]] || fail binary 'Release-Binary fehlt oder ist nicht ausfuehrbar.'

binary_abs="$(realpath "$binary")"
tmp_dir="$(mktemp -d)"
container_name="iscy-portable-runtime-${RANDOM}-$$"
container_user_args=(--user "$(id -u):$(id -g)")
if [[ "$(basename "$container_engine")" == podman ]]; then
    container_user_args+=(--userns keep-id)
fi
cleanup() {
    "$container_engine" rm -f "$container_name" >/dev/null 2>&1 || true
    rm -rf "$tmp_dir"
}
trap cleanup EXIT

runtime_args=(
    --rm
    --network none
    --read-only
    --cap-drop ALL
    --security-opt no-new-privileges
    "${container_user_args[@]}"
    --mount "type=bind,src=$binary_abs,dst=/usr/local/bin/iscy-backend,readonly"
)

"$container_engine" run "${runtime_args[@]}" "$runtime_image" \
    sh -eu -c "
        for command in nix rustc cargo cc gcc; do
            if command -v \"\$command\" >/dev/null 2>&1; then
                exit 1
            fi
        done
        ldd /usr/local/bin/iscy-backend | grep -qv \"not found\"
        ! ldd /usr/local/bin/iscy-backend | grep -q \"/nix/store/\"
        /usr/local/bin/iscy-backend --help >/dev/null
    "

mkdir -p "$tmp_dir/runtime"
"$container_engine" run "${runtime_args[@]}" \
    --mount "type=bind,src=$tmp_dir/runtime,dst=/var/lib/iscy" \
    --workdir /var/lib/iscy \
    --env DATABASE_URL=sqlite:////var/lib/iscy/iscy.sqlite3 \
    --env ISCY_MEDIA_ROOT=/var/lib/iscy/media \
    "$runtime_image" /usr/local/bin/iscy-backend init-demo >"$tmp_dir/init.log" 2>&1

"$container_engine" run -d \
    --name "$container_name" \
    --read-only \
    --cap-drop ALL \
    --security-opt no-new-privileges \
    "${container_user_args[@]}" \
    --tmpfs /tmp:rw,noexec,nosuid,nodev,size=16m \
    --mount "type=bind,src=$binary_abs,dst=/usr/local/bin/iscy-backend,readonly" \
    --mount "type=bind,src=$tmp_dir/runtime,dst=/var/lib/iscy" \
    --workdir /var/lib/iscy \
    --publish 127.0.0.1::9000 \
    --env DATABASE_URL=sqlite:////var/lib/iscy/iscy.sqlite3 \
    --env ISCY_MEDIA_ROOT=/var/lib/iscy/media \
    --env RUST_BACKEND_BIND=0.0.0.0:9000 \
    "$runtime_image" /usr/local/bin/iscy-backend >"$tmp_dir/container-id"

host_port="$("$container_engine" port "$container_name" 9000/tcp | sed -n 's/.*://p' | head -n 1)"
[[ "$host_port" =~ ^[0-9]+$ ]] || fail runtime 'Zugewiesener Testport konnte nicht ermittelt werden.'
for _ in $(seq 1 60); do
    if curl -fsS "http://127.0.0.1:$host_port/health/live" >/dev/null 2>&1; then
        break
    fi
    if ! "$container_engine" inspect -f '{{.State.Running}}' "$container_name" 2>/dev/null | grep -qx true; then
        fail runtime 'Backend wurde im sauberen Runtime-Container vorzeitig beendet.'
    fi
    sleep 1
done
curl -fsS "http://127.0.0.1:$host_port/health/live" >/dev/null \
    || fail runtime 'Health-Smoke im sauberen Runtime-Container fehlgeschlagen.'
"$container_engine" stop --time 20 "$container_name" >/dev/null
"$container_engine" logs "$container_name" >"$tmp_dir/runtime.log" 2>&1 || true

if grep -aEq '/home/[^/]+/|/tmp/(ISCY|iscy|rustc|cargo|build)|/nix/store/' \
    "$tmp_dir/init.log" "$tmp_dir/runtime.log"; then
    fail log_hygiene 'Runtime-Log enthaelt einen lokalen Buildpfad; Fundwert redigiert.'
fi
if grep -aEq '(postgres(ql)?|mysql|mongodb(\+srv)?|redis)://[^[:space:]"<>]+:[^[:space:]"<>]+@' \
    "$tmp_dir/init.log" "$tmp_dir/runtime.log"; then
    fail log_hygiene 'Runtime-Log enthaelt eine credential-haltige URL; Fundwert redigiert.'
fi

echo 'PORTABILITY_OK: Debian-Bookworm-Runtime ohne Nix/Rust/Cargo/Compiler, SQLite-Startup, Health und Shutdown erfolgreich.'
