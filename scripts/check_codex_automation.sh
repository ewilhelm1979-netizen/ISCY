#!/usr/bin/env bash
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

scripts=(.github/scripts/iscy_codex_*.sh)
tests=(tests/automation/test_iscy_codex_*.sh)
workflows=(
  .github/workflows/iscy-codex-command.yml
  .github/workflows/iscy-codex-ci-loop.yml
  .github/workflows/iscy-codex-reusable.yml
)

for command in jq shellcheck actionlint ruby; do
  command -v "$command" >/dev/null 2>&1 || {
    printf 'CODEX_AUTOMATION_CHECK prerequisite_missing=%s\n' "$command" >&2
    exit 1
  }
done

bash -n "${scripts[@]}" "${tests[@]}"
shellcheck "${scripts[@]}" "${tests[@]}"
actionlint "${workflows[@]}"
ruby -e '
  require "yaml"
  ARGV.each do |path|
    parsed = YAML.safe_load(File.read(path), aliases: true)
    abort("invalid YAML document: #{path}") unless parsed.is_a?(Hash)
  end
' "${workflows[@]}"
jq -e '.type == "object" and .additionalProperties == false' \
  .codex/schemas/result.schema.json >/dev/null

if grep -En 'uses:[[:space:]]+[^#[:space:]]+@(v[0-9]+|main|master)([[:space:]#]|$)' \
  "${workflows[@]}"; then
  echo 'CODEX_AUTOMATION_CHECK moving_action_ref_detected' >&2
  exit 1
fi
if grep -En 'pull_request_target|auto-merge|mergePullRequest|markPullRequestReadyForReview' \
  "${workflows[@]}"; then
  echo 'CODEX_AUTOMATION_CHECK prohibited_workflow_capability_detected' >&2
  exit 1
fi
sha_checkout_count="$(grep -Fc 'ref: ${{ inputs.commit_sha }}' \
  .github/workflows/iscy-codex-reusable.yml)"
if [[ "$sha_checkout_count" != '3' ]]; then
  echo 'CODEX_AUTOMATION_CHECK immutable_pr_checkout_count_invalid' >&2
  exit 1
fi
if grep -En 'ref:[[:space:]]+\$\{\{[[:space:]]*inputs\.(expected_head|head_ref)' \
  .github/workflows/iscy-codex-reusable.yml; then
  echo 'CODEX_AUTOMATION_CHECK mutable_pr_checkout_input_detected' >&2
  exit 1
fi

for test_file in "${tests[@]}"; do
  bash "$test_file"
done

bash scripts/check_release_sensitive_data.sh
git diff --check

echo 'CODEX_AUTOMATION_CHECK OK'
