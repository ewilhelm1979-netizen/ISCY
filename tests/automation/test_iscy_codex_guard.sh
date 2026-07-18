#!/usr/bin/env bash
set -euo pipefail
umask 077

repo_root="$(git rev-parse --show-toplevel)"
guard="$repo_root/.github/scripts/iscy_codex_guard.sh"
collector="$repo_root/.github/scripts/iscy_codex_collect_ci.sh"
tmp_dir="$(mktemp -d)"
trap 'rm -rf -- "$tmp_dir"' EXIT INT TERM

fail() {
  printf 'test_iscy_codex_guard: %s\n' "$1" >&2
  exit 1
}

expect_success() {
  "$@" >/dev/null 2>&1 || fail "Erwarteter Erfolg blieb aus: $*"
}

expect_failure() {
  if "$@" >/dev/null 2>&1; then
    fail "Erwarteter Fehler blieb aus: $*"
  fi
}

run_command() {
  ISCY_COMMAND_TEXT="$1" bash "$guard" command
}

run_pr() {
  local actor="$1"
  local repository="$2"
  local author="$3"
  local draft="$4"
  local labels="$5"
  local head_repository="$6"
  local head_ref="$7"
  local mode="${8:-manual}"
  ISCY_REPOSITORY="$repository" \
    ISCY_EVENT_ACTOR="$actor" \
    ISCY_EVENT_ASSOCIATION='OWNER' \
    ISCY_COMMAND='review' \
    ISCY_PR_AUTHOR="$author" \
    ISCY_PR_STATE='open' \
    ISCY_PR_DRAFT="$draft" \
    ISCY_PR_BASE_REF='main' \
    ISCY_PR_BASE_SHA='1111111111111111111111111111111111111111' \
    ISCY_PR_HEAD_REPOSITORY="$head_repository" \
    ISCY_PR_HEAD_REF="$head_ref" \
    ISCY_PR_HEAD_SHA='2222222222222222222222222222222222222222' \
    ISCY_PR_LABELS="$labels" \
    bash "$guard" pr "$mode"
}

for command in status review fix-ci verify; do
  actual="$(run_command " /iscy $command ")"
  [[ "$actual" == "$command" ]] || fail "Kommando $command wurde falsch geparst."
done
expect_failure run_command '/iscy unknown'
expect_failure run_command '/iscy review now'
expect_failure run_command '/iscy review; id'
expect_failure run_command '/iscy review | id'
expect_failure run_command $'/iscy review\nid'
code_fence='```'
expect_failure run_command "${code_fence}/iscy review${code_fence}"
expect_failure run_command '/ISCY review'

valid_repo='ewilhelm1979-netizen/ISCY'
valid_labels=$'codex-approved\ncodex-managed'
expect_success run_pr 'ewilhelm1979-netizen' "$valid_repo" \
  'ewilhelm1979-netizen' true "$valid_labels" "$valid_repo" feature/test
expect_success run_pr 'github-actions[bot]' "$valid_repo" \
  'ewilhelm1979-netizen' true "$valid_labels" "$valid_repo" feature/test automatic
expect_failure run_pr intruder "$valid_repo" \
  'ewilhelm1979-netizen' true "$valid_labels" "$valid_repo" feature/test automatic
expect_failure run_pr intruder "$valid_repo" \
  'ewilhelm1979-netizen' true "$valid_labels" "$valid_repo" feature/test
expect_failure run_pr 'ewilhelm1979-netizen' other/ISCY \
  'ewilhelm1979-netizen' true "$valid_labels" "$valid_repo" feature/test
expect_failure run_pr 'ewilhelm1979-netizen' "$valid_repo" \
  intruder true "$valid_labels" "$valid_repo" feature/test
expect_failure run_pr 'ewilhelm1979-netizen' "$valid_repo" \
  'ewilhelm1979-netizen' false "$valid_labels" "$valid_repo" feature/test
expect_failure run_pr 'ewilhelm1979-netizen' "$valid_repo" \
  'ewilhelm1979-netizen' true 'codex-managed' "$valid_repo" feature/test
expect_failure run_pr 'ewilhelm1979-netizen' "$valid_repo" \
  'ewilhelm1979-netizen' true "$valid_labels" someone/ISCY feature/test
expect_failure run_pr 'ewilhelm1979-netizen' "$valid_repo" \
  'ewilhelm1979-netizen' true "$valid_labels" "$valid_repo" dependabot/cargo/test
expect_failure run_pr 'ewilhelm1979-netizen' "$valid_repo" \
  'ewilhelm1979-netizen' true "$valid_labels" "$valid_repo" main

wrong_head='3333333333333333333333333333333333333333'
expected_head='4444444444444444444444444444444444444444'
jq -n \
  --arg head "$wrong_head" \
  '{check_runs:[
    "rust-backend-tests", "rust-msrv-1.88", "rust-bootstrap-smoke",
    "nix-rust-smoke", "object-storage-integration", "performance-smoke",
    "ha-integration", "visual-regression", "docker-config",
    "release-binary-portability", "codex-automation-tests", "release-candidate-check",
    "Analyze (actions)", "Analyze (javascript-typescript)", "Analyze (rust)"
  ] | map({name:., app:{slug:"github-actions"}, head_sha:$head, status:"completed", conclusion:"success"})
  + [{name:"CodeQL", app:{slug:"github-advanced-security"}, head_sha:$head, status:"completed", conclusion:"success"}]}' \
  >"$tmp_dir/checks.json"
bash "$collector" summarize "$tmp_dir/checks.json" "$expected_head" "$tmp_dir/summary.json"
[[ "$(jq -r '.all_green' "$tmp_dir/summary.json")" == 'false' ]] \
  || fail 'Checks eines fremden Workflow-Heads wurden akzeptiert.'
[[ "$(jq -r '.required_present' "$tmp_dir/summary.json")" == '0' ]] \
  || fail 'Checks eines fremden Workflow-Heads wurden zugeordnet.'

jq -n '{
  action:"review", status:"READY_FOR_HUMAN_REVIEW", summary:"OK", root_cause:"",
  changed_files:[], tests_run:[], tests_passed:true, blockers:[], security_notes:[],
  scope_notes:[], recommended_human_action:"Menschliche Review durchfuehren."
}' >"$tmp_dir/result.json"
expect_success bash "$guard" result "$tmp_dir/result.json" review
jq '.unexpected = true' "$tmp_dir/result.json" >"$tmp_dir/result-extra.json"
expect_failure bash "$guard" result "$tmp_dir/result-extra.json" review
danger_result='gh''p_0123456789abcdefghijklmnop'
jq --arg value "$danger_result" '.summary = $value' "$tmp_dir/result.json" \
  >"$tmp_dir/result-secret.json"
expect_failure bash "$guard" result "$tmp_dir/result-secret.json" review
danger_result_path='/'"home"'/test-user/private/result.txt'
jq --arg value "$danger_result_path" '.summary = $value' "$tmp_dir/result.json" \
  >"$tmp_dir/result-path.json"
expect_failure bash "$guard" result "$tmp_dir/result-path.json" review

echo 'test_iscy_codex_guard: OK'
