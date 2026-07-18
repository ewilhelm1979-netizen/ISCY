#!/usr/bin/env bash
set -euo pipefail
umask 077

repo_root="$(git rev-parse --show-toplevel)"
diff_guard="$repo_root/.github/scripts/iscy_codex_validate_diff.sh"
tmp_root="$(mktemp -d)"
trap 'rm -rf -- "$tmp_root"' EXIT INT TERM
case_no=0

fail() {
  printf 'test_iscy_codex_diff_guard: %s\n' "$1" >&2
  exit 1
}

new_repo() {
  case_no=$((case_no + 1))
  test_repo="$tmp_root/case-$case_no"
  mkdir -p "$test_repo/scripts"
  git -C "$test_repo" init -q
  git -C "$test_repo" config user.name 'ISCY Test'
  git -C "$test_repo" config user.email 'iscy-test@example.invalid'
  printf 'base\n' >"$test_repo/base.txt"
  printf '#!/usr/bin/env bash\nexit 0\n' >"$test_repo/scripts/scanner.sh"
  git -C "$test_repo" add base.txt scripts/scanner.sh
  git -C "$test_repo" commit -qm base
  git -C "$test_repo" switch -qc feature/test
  test_head="$(git -C "$test_repo" rev-parse HEAD)"
}

run_guard() {
  ISCY_TEST_MODE=true \
    ISCY_REMOTE_HEAD_OVERRIDE="${remote_override:-$test_head}" \
    ISCY_TRUSTED_SCANNER="$test_repo/scripts/scanner.sh" \
    bash "$diff_guard" "$test_repo" "$test_head" feature/test false
}

expect_success() {
  local output
  if ! output="$(run_guard 2>&1)"; then
    printf '%s\n' "$output" >&2
    fail "$1"
  fi
}

expect_failure() {
  if run_guard >/dev/null 2>&1; then
    fail "$1"
  fi
}

new_repo
printf 'safe\n' >"$test_repo/change.txt"
expect_success 'Ein sicherer Diff wurde abgelehnt.'

new_repo
set +e
run_guard >/dev/null 2>&1
status=$?
set -e
[[ "$status" -eq 3 ]] || fail 'Ein leerer Diff wurde nicht mit Status 3 beendet.'

new_repo
mkdir -p "$test_repo/.github/workflows"
printf 'name: blocked\n' >"$test_repo/.github/workflows/blocked.yml"
expect_failure 'Eine geschuetzte Workflow-Datei wurde akzeptiert.'

new_repo
mkdir -p "$test_repo/.codex/runtime/ci"
printf 'runtime\n' >"$test_repo/.codex/runtime/ci/output.txt"
expect_failure '.codex/runtime wurde im Diff akzeptiert.'

new_repo
danger_secret='gh''p_0123456789abcdefghijklmnop'
printf '%s\n' "$danger_secret" >"$test_repo/change.txt"
expect_failure 'Ein Secret-Marker wurde akzeptiert.'

new_repo
danger_path='/'"home"'/test-user/private/file.txt'
printf '%s\n' "$danger_path" >"$test_repo/change.txt"
expect_failure 'Ein lokaler absoluter Pfad wurde akzeptiert.'

new_repo
printf '\000\001\002' >"$test_repo/payload.bin"
expect_failure 'Eine nicht freigegebene Binardatei wurde akzeptiert.'

new_repo
ln -s base.txt "$test_repo/link.txt"
expect_failure 'Ein Symlink wurde akzeptiert.'

new_repo
printf 'race\n' >"$test_repo/change.txt"
remote_override='5555555555555555555555555555555555555555'
expect_failure 'Ein Remote-Head-Race wurde akzeptiert.'
unset remote_override

echo 'test_iscy_codex_diff_guard: OK'
