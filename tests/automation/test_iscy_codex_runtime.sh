#!/usr/bin/env bash
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

tmp_dir="$(mktemp -d)"
cleanup() {
  rm -rf -- "$tmp_dir"
}
trap cleanup EXIT INT TERM

fail() {
  printf 'test_iscy_codex_runtime: %s\n' "$1" >&2
  exit 1
}

workflow='.github/workflows/iscy-codex-reusable.yml'
ruby - "$workflow" "$tmp_dir" <<'RUBY'
require "yaml"

workflow = YAML.safe_load(File.read(ARGV.fetch(0)), aliases: true)
steps = workflow.fetch("jobs").fetch("review-or-verify").fetch("steps")
step_by_name = steps.to_h { |step| [step.fetch("name"), step] }
fix_steps = workflow.fetch("jobs").fetch("fix-agent").fetch("steps")

prepare = step_by_name.fetch("Prepare trusted read-only context").fetch("run")
package_preflight = step_by_name.fetch("Resolve pinned Codex runtime packages")
preflight = step_by_name.fetch("Authenticate OpenAI API without model request")
codex = steps.find { |step| step["id"] == "codex" }
abort("Codex step missing") unless codex
codex_with = codex.fetch("with")
diagnose = step_by_name.fetch("Diagnose Codex action runtime")
fix_codex = fix_steps.find { |step| step["id"] == "codex" }
abort("Fix-agent Codex step missing") unless fix_codex
fix_codex_with = fix_codex.fetch("with")
validate = step_by_name.fetch("Validate structured result")
upload = step_by_name.fetch("Upload bounded result").fetch("with")

abort("Codex output-file retained") if codex_with.key?("output-file")
abort("prompt is not inside the worktree runtime") unless codex_with["prompt-file"] ==
  "${{ github.workspace }}/worktree/.codex/runtime/input/prompt.md"
abort("schema is not inside the worktree runtime") unless codex_with["output-schema-file"] ==
  "${{ github.workspace }}/worktree/.codex/runtime/input/result.schema.json"
abort("read-only permission profile changed") unless codex_with["permission-profile"] == ":read-only"
abort("drop-sudo strategy changed") unless codex_with["safety-strategy"] == "drop-sudo"
abort("allowed user changed") unless codex_with["allow-users"] == "ewilhelm1979-netizen"
abort("bot boundary changed") unless codex_with["allow-bots"] == false
abort("review Codex version changed") unless codex_with["codex-version"] == "0.144.4"
abort("fix-agent permission profile changed") unless
  fix_codex_with["permission-profile"] == ":workspace"
abort("fix-agent drop-sudo strategy changed") unless
  fix_codex_with["safety-strategy"] == "drop-sudo"
abort("fix-agent Codex version changed") unless
  fix_codex_with["codex-version"] == "0.144.4"
abort("Codex versions differ between review and fix-agent") unless
  codex_with["codex-version"] == fix_codex_with["codex-version"]
abort("Codex action is not diagnostic-only continue-on-error") unless
  codex["continue-on-error"] == true

continue_steps = workflow.fetch("jobs").flat_map do |job_name, job|
  job.fetch("steps", []).filter_map do |step|
    [job_name, step["id"]] if step["continue-on-error"] == true
  end
end
abort("continue-on-error is not restricted to the review Codex action") unless
  continue_steps == [["review-or-verify", "codex"]]

[
  "worktree/.codex/runtime/input/prompt.md",
  "worktree/.codex/runtime/input/result.schema.json"
].each do |path|
  abort("runtime input path missing: #{path}") unless prepare.include?(path)
end
abort("legacy runner-temp input retained") if prepare.include?("iscy-codex-input")

package_run = package_preflight.fetch("run")
abort("CLI package preflight missing") unless
  package_run.include?("npm view \"$package\" version") &&
  package_run.include?("'@openai/codex@0.144.4'")
abort("proxy package preflight missing") unless
  package_run.include?("'@openai/codex-responses-api-proxy@0.144.4'")
abort("package preflight is not fail closed") unless
  package_run.include?('ISCY_CODEX_RUNTIME_ERROR[$phase]') &&
  package_run.include?("exit 1")
abort("package preflight does not clean temporary output") unless
  package_run.include?('rm -f -- "$output_file"') &&
  package_run.include?('rm -rf -- "$package_dir"')

preflight_env = preflight.fetch("env")
abort("OpenAI key is not sourced from the existing secret") unless
  preflight_env["OPENAI_API_KEY"] == "${{ secrets.openai_api_key }}"
preflight_run = preflight.fetch("run")
abort("OpenAI models preflight missing") unless
  preflight_run.include?("https://api.openai.com/v1/models")
abort("paid Responses request introduced") if preflight_run.include?("/v1/responses")
abort("shell tracing would expose secrets") if preflight_run.include?("set -x")

diagnose_env = diagnose.fetch("env")
abort("Codex outcome is not wired to runtime diagnosis") unless
  diagnose_env["ISCY_CODEX_OUTCOME"] == "${{ steps.codex.outcome }}"
abort("final-message is not wired to runtime diagnosis") unless
  diagnose_env["ISCY_FINAL_MESSAGE"] == "${{ steps.codex.outputs.final-message }}"
abort("runtime diagnosis is not unconditional") unless diagnose["if"] == "always()"
diagnose_run = diagnose.fetch("run")
[
  "command -v codex",
  "codex --version",
  "command -v codex-responses-api-proxy",
  "codex-responses-api-proxy --help",
  "ISCY_CODEX_RUNTIME[CLI_INSTALL_OR_LAUNCH]",
  "ISCY_CODEX_RUNTIME[PROXY_INSTALL_OR_LAUNCH]",
  "ISCY_CODEX_RUNTIME[CODEX_EXEC]",
  "ISCY_CODEX_RUNTIME[FINAL_MESSAGE]",
  "ISCY_CODEX_RUNTIME[FINAL_MESSAGE_BYTES]"
].each do |fragment|
  abort("runtime diagnosis missing: #{fragment}") unless diagnose_run.include?(fragment)
end
abort("runtime diagnosis is not fail closed") unless
  diagnose_run.include?('ISCY_CODEX_RUNTIME_ERROR[$failed_phase]') &&
  diagnose_run.include?("ISCY_CODEX_RESULT_ERROR: final-message is empty") &&
  diagnose_run.scan("exit 1").length >= 2
abort("runtime diagnosis enables shell tracing") if diagnose_run.include?("set -x")

codex_index = steps.index(codex)
diagnose_index = steps.index(diagnose)
validate_index = steps.index(validate)
abort("runtime diagnosis is not directly after the Codex action") unless
  diagnose_index == codex_index + 1
abort("structured validation can run before runtime diagnosis") unless
  validate_index == diagnose_index + 1

validate_env = validate.fetch("env")
abort("final-message output is not wired to validation") unless
  validate_env["ISCY_FINAL_MESSAGE"] == "${{ steps.codex.outputs.final-message }}"
validate_run = validate.fetch("run")
abort("existing result guard removed") unless
  validate_run.include?("iscy_codex_guard.sh result")
abort("bounded result path changed") unless
  validate_run.include?('$RUNNER_TEMP/iscy-codex-result')
abort("upload path changed") unless
  upload.fetch("path") == "${{ runner.temp }}/iscy-codex-result/result.json"

File.write(File.join(ARGV.fetch(1), "preflight.sh"), preflight_run)
File.write(File.join(ARGV.fetch(1), "package-preflight.sh"), package_run)
File.write(File.join(ARGV.fetch(1), "diagnose.sh"), diagnose_run)
File.write(File.join(ARGV.fetch(1), "validate.sh"), validate_run)
RUBY

validation_script="$tmp_dir/validate.sh"
valid_result="$(jq -cn '{
  action: "review",
  status: "READY_FOR_HUMAN_REVIEW",
  summary: "runtime-final-message-canary",
  root_cause: "",
  changed_files: [],
  tests_run: [],
  tests_passed: true,
  blockers: [],
  security_notes: [],
  scope_notes: [],
  recommended_human_action: "Review the result"
}')"

run_validation_case() {
  local name="$1"
  local payload="$2"
  local dirty="${3:-false}"
  case_root="$tmp_dir/validation-$name"
  case_log="$case_root/output.log"
  mkdir -p \
    "$case_root/runner" \
    "$case_root/trusted/.github/scripts" \
    "$case_root/worktree"
  cp .github/scripts/iscy_codex_guard.sh \
    "$case_root/trusted/.github/scripts/iscy_codex_guard.sh"
  git -C "$case_root/worktree" init -q
  if [[ "$dirty" == 'true' ]]; then
    printf 'original\n' >"$case_root/worktree/tracked.txt"
    git -C "$case_root/worktree" add tracked.txt
    git -C "$case_root/worktree" \
      -c user.name='ISCY Test' -c user.email='iscy-test@invalid.example' \
      commit -qm 'test fixture'
    printf 'changed\n' >"$case_root/worktree/tracked.txt"
  fi
  if (
    cd "$case_root"
    RUNNER_TEMP="$case_root/runner" \
      ISCY_ROUTE='review' \
      ISCY_FINAL_MESSAGE="$payload" \
      bash "$validation_script"
  ) >"$case_log" 2>&1; then
    case_status=0
  else
    case_status=$?
  fi
}

run_validation_case missing ''
(( case_status != 0 )) || fail 'missing final-message was accepted'
grep -Fq 'ISCY_CODEX_RESULT_ERROR: final-message is empty' "$case_log" \
  || fail 'missing final-message annotation absent'

printf -v oversized_result '%*s' 65537 ''
oversized_result="${oversized_result// /x}"
run_validation_case oversized "$oversized_result"
(( case_status != 0 )) || fail 'oversized final-message was accepted'
grep -Fq 'final-message size is outside 1..65536 bytes' "$case_log" \
  || fail 'oversized final-message annotation absent'
grep -Fq "$oversized_result" "$case_log" \
  && fail 'oversized final-message leaked into the log'

invalid_result='{invalid-json-runtime-canary'
run_validation_case invalid-json "$invalid_result"
(( case_status != 0 )) || fail 'invalid JSON was accepted'
grep -Fq 'final-message is not valid JSON' "$case_log" \
  || fail 'invalid JSON annotation absent'
grep -Fq "$invalid_result" "$case_log" \
  && fail 'invalid final-message leaked into the log'

schema_violation='{"action":"review"}'
run_validation_case schema-violation "$schema_violation"
(( case_status != 0 )) || fail 'schema violation was accepted'
grep -Fq 'ISCY_CODEX_GUARD_ERROR[result]' "$case_log" \
  || fail 'schema violation did not reach the existing guard'

run_validation_case dirty-worktree "$valid_result" true
(( case_status != 0 )) || fail 'tracked worktree change was accepted'
grep -Fq 'tracked worktree changes detected' "$case_log" \
  || fail 'tracked worktree annotation absent'

run_validation_case valid "$valid_result"
(( case_status == 0 )) || fail 'valid final-message was rejected'
result_file="$case_root/runner/iscy-codex-result/result.json"
[[ -f "$result_file" ]] || fail 'bounded result was not materialized'
printf '%s' "$valid_result" >"$tmp_dir/expected-result.json"
cmp -s "$tmp_dir/expected-result.json" "$result_file" \
  || fail 'materialized result differs from final-message'
grep -Fq 'runtime-final-message-canary' "$case_log" \
  && fail 'valid final-message leaked into the log'

fake_bin="$tmp_dir/fake-bin"
mkdir -p "$fake_bin"
cat >"$fake_bin/curl" <<'FAKE_CURL'
#!/usr/bin/env bash
set -euo pipefail
output=''
while (( $# > 0 )); do
  case "$1" in
    --output)
      output="$2"
      shift 2
      ;;
    --header|--request|--proto|--connect-timeout|--max-time|--write-out)
      shift 2
      ;;
    --silent|--tlsv1.2)
      shift
      ;;
    *)
      shift
      ;;
  esac
done
[[ -n "$output" ]]
printf '{"object":"list"}' >"$output"
printf '%s' "${FAKE_CURL_STATUS:-200}"
exit "${FAKE_CURL_EXIT:-0}"
FAKE_CURL
chmod +x "$fake_bin/curl"

run_preflight_case() {
  local name="$1"
  local status="$2"
  preflight_root="$tmp_dir/preflight-$name"
  preflight_log="$preflight_root/output.log"
  mkdir -p "$preflight_root/runner"
  if PATH="$fake_bin:$PATH" \
    RUNNER_TEMP="$preflight_root/runner" \
    OPENAI_API_KEY='runtime-auth-key-canary' \
    FAKE_CURL_STATUS="$status" \
    bash "$tmp_dir/preflight.sh" >"$preflight_log" 2>&1; then
    preflight_status=0
  else
    preflight_status=$?
  fi
  grep -Fq 'runtime-auth-key-canary' "$preflight_log" \
    && fail "OpenAI key leaked in $name preflight"
  grep -Fq '{"object":"list"}' "$preflight_log" \
    && fail "OpenAI response body leaked in $name preflight"
  leftover="$(find "$preflight_root/runner" -type f -print -quit)"
  [[ -z "$leftover" ]] || fail "OpenAI response file retained in $name preflight"
}

run_preflight_case success 200
(( preflight_status == 0 )) || fail 'HTTP 200 preflight failed'
grep -Fxq 'OpenAI preflight HTTP 200' "$preflight_log" \
  || fail 'HTTP 200 preflight logged unexpected data'

run_preflight_case unauthorized 401
(( preflight_status != 0 )) || fail 'HTTP 401 preflight succeeded'
grep -Fq 'ISCY_CODEX_OPENAI_PREFLIGHT_ERROR: HTTP 401' "$preflight_log" \
  || fail 'HTTP 401 preflight annotation absent'

package_fake_bin="$tmp_dir/package-fake-bin"
mkdir -p "$package_fake_bin"
cat >"$package_fake_bin/npm" <<'FAKE_NPM'
#!/usr/bin/env bash
set -euo pipefail
[[ "${1:-}" == 'view' && "${3:-}" == 'version' ]]
case "${2:-}" in
  '@openai/codex@0.144.4')
    phase='cli'
    ;;
  '@openai/codex-responses-api-proxy@0.144.4')
    phase='proxy'
    ;;
  *)
    exit 2
    ;;
esac
if [[ "${FAKE_NPM_MISSING:-}" == "$phase" ]]; then
  printf 'npm-package-metadata-canary\n'
  printf 'npm-package-error-canary\n' >&2
  exit 1
fi
printf '0.144.4\n'
FAKE_NPM
chmod +x "$package_fake_bin/npm"

run_package_case() {
  local name="$1"
  local missing="$2"
  package_root="$tmp_dir/package-$name"
  package_log="$package_root/output.log"
  mkdir -p "$package_root/runner"
  if PATH="$package_fake_bin:$PATH" \
    RUNNER_TEMP="$package_root/runner" \
    FAKE_NPM_MISSING="$missing" \
    bash "$tmp_dir/package-preflight.sh" >"$package_log" 2>&1; then
    package_status=0
  else
    package_status=$?
  fi
  grep -Fq 'npm-package-metadata-canary' "$package_log" \
    && fail "npm metadata leaked in $name package preflight"
  grep -Fq 'npm-package-error-canary' "$package_log" \
    && fail "npm error output leaked in $name package preflight"
  leftover="$(find "$package_root/runner" -type f -print -quit)"
  [[ -z "$leftover" ]] || fail "npm output file retained in $name package preflight"
}

run_package_case cli-missing cli
(( package_status != 0 )) || fail 'missing CLI package was accepted'
grep -Fq 'ISCY_CODEX_RUNTIME_ERROR[CLI_PACKAGE_RESOLUTION]' "$package_log" \
  || fail 'missing CLI package annotation absent'

run_package_case proxy-missing proxy
(( package_status != 0 )) || fail 'missing proxy package was accepted'
grep -Fxq 'ISCY_CODEX_RUNTIME[CLI_PACKAGE_RESOLUTION]: OK' "$package_log" \
  || fail 'CLI package success was not reported before proxy failure'
grep -Fq 'ISCY_CODEX_RUNTIME_ERROR[PROXY_PACKAGE_RESOLUTION]' "$package_log" \
  || fail 'missing proxy package annotation absent'

run_package_case success ''
(( package_status == 0 )) || fail 'valid pinned packages were rejected'
grep -Fxq 'ISCY_CODEX_RUNTIME[CLI_PACKAGE_RESOLUTION]: OK' "$package_log" \
  || fail 'CLI package success notice absent'
grep -Fxq 'ISCY_CODEX_RUNTIME[PROXY_PACKAGE_RESOLUTION]: OK' "$package_log" \
  || fail 'proxy package success notice absent'
[[ "$(wc -l <"$package_log")" -eq 2 ]] \
  || fail 'successful package preflight logged unexpected data'

diagnose_script="$tmp_dir/diagnose.sh"
bash_path="$(command -v bash)"
wc_path="$(command -v wc)"

run_diagnose_case() {
  local name="$1"
  local cli_present="$2"
  local proxy_present="$3"
  local action_outcome="$4"
  local final_message="$5"
  diagnose_root="$tmp_dir/diagnose-$name"
  diagnose_bin="$diagnose_root/bin"
  diagnose_log="$diagnose_root/output.log"
  mkdir -p "$diagnose_bin"
  ln -s "$wc_path" "$diagnose_bin/wc"
  if [[ "$cli_present" == 'true' ]]; then
    cat >"$diagnose_bin/codex" <<'FAKE_CODEX'
#!/bin/sh
printf 'codex-version-output-canary\n'
exit 0
FAKE_CODEX
    chmod +x "$diagnose_bin/codex"
  fi
  if [[ "$proxy_present" == 'true' ]]; then
    cat >"$diagnose_bin/codex-responses-api-proxy" <<'FAKE_PROXY'
#!/bin/sh
printf 'proxy-help-output-canary\n'
exit 0
FAKE_PROXY
    chmod +x "$diagnose_bin/codex-responses-api-proxy"
  fi
  if PATH="$diagnose_bin" \
    OPENAI_API_KEY='runtime-auth-key-canary' \
    ISCY_PROMPT='runtime-prompt-canary' \
    ISCY_CODEX_OUTCOME="$action_outcome" \
    ISCY_FINAL_MESSAGE="$final_message" \
    "$bash_path" "$diagnose_script" >"$diagnose_log" 2>&1; then
    diagnose_status=0
  else
    diagnose_status=$?
  fi
  for forbidden in \
    'runtime-auth-key-canary' \
    'runtime-prompt-canary' \
    'codex-version-output-canary' \
    'proxy-help-output-canary' \
    "$final_message"; do
    [[ -z "$forbidden" ]] && continue
    grep -Fq "$forbidden" "$diagnose_log" \
      && fail "sensitive or command output leaked in $name diagnosis"
  done
  return 0
}

diagnostic_message='runtime-final-message-diagnostic-canary'
run_diagnose_case cli-missing false true failure "$diagnostic_message"
(( diagnose_status != 0 )) || fail 'missing Codex binary was accepted'
grep -Fq 'ISCY_CODEX_RUNTIME_ERROR[CLI_INSTALL_OR_LAUNCH]' "$diagnose_log" \
  || fail 'missing Codex binary phase annotation absent'

run_diagnose_case proxy-missing true false failure "$diagnostic_message"
(( diagnose_status != 0 )) || fail 'missing proxy binary was accepted'
grep -Fq 'ISCY_CODEX_RUNTIME_ERROR[PROXY_INSTALL_OR_LAUNCH]' "$diagnose_log" \
  || fail 'missing proxy binary phase annotation absent'

run_diagnose_case action-failure true true failure "$diagnostic_message"
(( diagnose_status != 0 )) || fail 'failed Codex action outcome was accepted'
grep -Fq 'ISCY_CODEX_RUNTIME_ERROR[CODEX_EXEC]' "$diagnose_log" \
  || fail 'Codex action failure phase annotation absent'

run_diagnose_case empty-message true true success ''
(( diagnose_status != 0 )) || fail 'empty diagnostic final-message was accepted'
grep -Fxq 'ISCY_CODEX_RUNTIME[FINAL_MESSAGE]: EMPTY' "$diagnose_log" \
  || fail 'empty diagnostic final-message status absent'
grep -Fq 'ISCY_CODEX_RESULT_ERROR: final-message is empty' "$diagnose_log" \
  || fail 'existing empty final-message annotation absent after diagnosis'

run_diagnose_case success true true success "$diagnostic_message"
(( diagnose_status == 0 )) || fail 'successful runtime diagnosis failed'
grep -Fxq 'ISCY_CODEX_RUNTIME[CLI_INSTALL_OR_LAUNCH]: OK' "$diagnose_log" \
  || fail 'successful Codex binary diagnosis absent'
grep -Fxq 'ISCY_CODEX_RUNTIME[PROXY_INSTALL_OR_LAUNCH]: OK' "$diagnose_log" \
  || fail 'successful proxy binary diagnosis absent'
grep -Fxq 'ISCY_CODEX_RUNTIME[CODEX_EXEC]: OK' "$diagnose_log" \
  || fail 'successful action outcome diagnosis absent'
grep -Fxq 'ISCY_CODEX_RUNTIME[FINAL_MESSAGE]: PRESENT' "$diagnose_log" \
  || fail 'present final-message diagnosis absent'
expected_bytes="$(LC_ALL=C printf '%s' "$diagnostic_message" | wc -c)"
grep -Fxq "ISCY_CODEX_RUNTIME[FINAL_MESSAGE_BYTES]: $expected_bytes" "$diagnose_log" \
  || fail 'final-message byte count is incorrect'
[[ "$(wc -l <"$diagnose_log")" -eq 5 ]] \
  || fail 'successful runtime diagnosis logged unexpected data'

echo 'test_iscy_codex_runtime: OK'
