#!/usr/bin/env bash
set -euo pipefail
umask 077

repo_root="$(git rev-parse --show-toplevel)"
guard="$repo_root/.github/scripts/iscy_codex_guard.sh"
tmp_dir="$(mktemp -d)"
trap 'rm -rf -- "$tmp_dir"' EXIT INT TERM

fail() {
  printf 'test_iscy_codex_attempt_limit: %s\n' "$1" >&2
  exit 1
}

assert_state() {
  local file="$1"
  local used="$2"
  local remaining="$3"
  local next="$4"
  local allowed="$5"
  local state
  state="$(bash "$guard" attempts "$file")"
  [[ "$(jq -r '.used' <<<"$state")" == "$used" ]] || fail 'used ist falsch.'
  [[ "$(jq -r '.remaining' <<<"$state")" == "$remaining" ]] || fail 'remaining ist falsch.'
  [[ "$(jq -r '.next' <<<"$state")" == "$next" ]] || fail 'next ist falsch.'
  [[ "$(jq -r '.allowed' <<<"$state")" == "$allowed" ]] || fail 'allowed ist falsch.'
}

printf '[]\n' >"$tmp_dir/zero.json"
assert_state "$tmp_dir/zero.json" 0 2 1 true

jq -n '[
  {user:{login:"github-actions[bot]"}, body:"<!-- iscy-codex-fix-attempt:1 -->"},
  {user:{login:"intruder"}, body:"<!-- iscy-codex-fix-attempt:2 -->"},
  {user:{login:"github-actions[bot]"}, body:"<!-- iscy-codex-fix-attempt:3 -->"},
  {user:{login:"github-actions[bot]"}, body:"prefix <!-- iscy-codex-fix-attempt:2 -->"}
]' >"$tmp_dir/one.json"
assert_state "$tmp_dir/one.json" 1 1 2 true

jq -n '[
  {user:{login:"github-actions[bot]"}, body:"<!-- iscy-codex-fix-attempt:1 -->"},
  {user:{login:"github-actions[bot]"}, body:"<!-- iscy-codex-fix-attempt:2 -->"},
  {user:{login:"github-actions[bot]"}, body:"<!-- iscy-codex-fix-attempt:2 -->"}
]' >"$tmp_dir/two.json"
assert_state "$tmp_dir/two.json" 2 0 0 false

echo 'test_iscy_codex_attempt_limit: OK'
