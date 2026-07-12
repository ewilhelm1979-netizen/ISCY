#!/usr/bin/env bash
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

binary="${1:-artifacts/portable-release/iscy-backend}"
container_engine="${ISCY_CONTAINER_ENGINE:-docker}"
runtime_image='docker.io/library/debian:bookworm-slim@sha256:1def178129dfb5f24db43afbf2fcac04530012e3264ba4ff81c71184e17a9ee4'
fail() {
    printf 'BINARY_HYGIENE_ERROR[%s]: %s\n' "$1" "$2" >&2
    exit 1
}

for command in file readelf sha256sum stat strings; do
    command -v "$command" >/dev/null 2>&1 || fail prerequisite "$command fehlt."
done
command -v "$container_engine" >/dev/null 2>&1 || fail prerequisite 'Container-Engine fehlt.'
[[ -f "$binary" && -x "$binary" ]] || fail binary 'Release-Binary fehlt oder ist nicht ausfuehrbar.'
binary_abs="$(realpath "$binary")"

file_output="$(file -b "$binary")"
[[ "$file_output" == *'ELF 64-bit LSB pie executable, x86-64'* ]] \
    || fail elf_format 'Erwartetes linux-x86_64 ELF-Format fehlt.'
[[ "$file_output" == *'stripped'* ]] || fail debug_artifact 'Binary ist nicht als stripped klassifiziert.'

interpreter="$(
    readelf -l "$binary" \
        | sed -n 's/.*Requesting program interpreter: \([^]]*\).*/\1/p'
)"
case "$interpreter" in
    /lib64/ld-linux-x86-64.so.2|/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2) ;;
    '') fail interpreter 'Dynamisches glibc-Binary besitzt keinen Interpreter.' ;;
    *) fail interpreter 'ELF-Interpreter liegt ausserhalb der erlaubten Systempfade.' ;;
esac
[[ "$interpreter" != *'/nix/store/'* ]] || fail interpreter 'ELF-Interpreter verweist auf den Nix Store.'

dynamic_tags="$(readelf -d "$binary")"
if grep -Eq '[(](RPATH|RUNPATH)[)]' <<<"$dynamic_tags"; then
    fail rpath 'RPATH oder RUNPATH ist im Release-Binary vorhanden.'
fi

ldd_output="$(
    "$container_engine" run --rm \
        --network none \
        --read-only \
        --cap-drop ALL \
        --security-opt no-new-privileges \
        --user "$(id -u):$(id -g)" \
        --mount "type=bind,src=$binary_abs,dst=/usr/local/bin/iscy-backend,readonly" \
        "$runtime_image" ldd /usr/local/bin/iscy-backend 2>&1
)" || fail ldd 'Dynamische Laufzeitabhaengigkeiten konnten im Zielcontainer nicht aufgeloest werden.'
[[ "$ldd_output" != *'not found'* ]] || fail ldd 'Mindestens eine Laufzeitbibliothek fehlt.'
[[ "$ldd_output" != *'/nix/store/'* ]] || fail ldd 'Laufzeitaufloesung verweist auf den Nix Store.'

strings_file="$(mktemp)"
cleanup() {
    rm -f "$strings_file"
}
trap cleanup EXIT
strings -a "$binary" >"$strings_file"

local_user="$(id -un 2>/dev/null || true)"
if grep -Eq '/home/[A-Za-z0-9._-]+/' "$strings_file"; then
    fail local_path 'Ein lokaler Home-Buildpfad wurde gefunden; Fundwert redigiert.'
fi
if [[ -n "$local_user" ]] && grep -Fq "/$local_user/" "$strings_file"; then
    fail local_user 'Der lokale Benutzername wurde im Binary gefunden; Fundwert redigiert.'
fi
if grep -Eq '/tmp/(ISCY|iscy|rustc|cargo|build)[^[:space:]]*|/[^[:space:]]*/_work/[^[:space:]]*' "$strings_file"; then
    fail temporary_path 'Ein temporaerer Build- oder Runner-Pfad wurde gefunden; Fundwert redigiert.'
fi
if grep -Fq "$repo_root" "$strings_file"; then
    fail repository_path 'Der lokale Repository-Pfad wurde gefunden; Fundwert redigiert.'
fi
if grep -Fq '/nix/store/' "$strings_file"; then
    fail nix_store 'Ein Nix-Store-Pfad wurde im Binary gefunden; Fundwert redigiert.'
fi

size_bytes="$(stat -c %s "$binary")"
(( size_bytes >= 1048576 && size_bytes <= 209715200 )) \
    || fail binary_size 'Binary-Groesse liegt ausserhalb des plausiblen Bereichs.'
sha256="$(sha256sum "$binary" | cut -d ' ' -f 1)"

printf 'BINARY_HYGIENE_OK: format=linux-x86_64-glibc stripped=yes rpath=absent local_paths=0 nix_store=0 size_bytes=%s sha256=%s\n' \
    "$size_bytes" "$sha256"
