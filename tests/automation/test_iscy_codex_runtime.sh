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
preflight = step_by_name.fetch("Authenticate OpenAI API without model request")
codex = steps.find { |step| step["id"] == "codex" }
abort("Codex step missing") unless codex
codex_with = codex.fetch("with")
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

[
  "worktree/.codex/runtime/input/prompt.md",
  "worktree/.codex/runtime/input/result.schema.json"
].each do |path|
  abort("runtime input path missing: #{path}") unless prepare.include?(path)
end
abort("legacy runner-temp input retained") if prepare.include?("iscy-codex-input")

preflight_env = preflight.fetch("env")
abort("OpenAI key is not sourced from the existing secret") unless
  preflight_env["OPENAI_API_KEY"] == "${{ secrets.openai_api_key }}"
preflight_run = preflight.fetch("run")
abort("OpenAI models preflight missing") unless
  preflight_run.include?("https://api.openai.com/v1/models")
abort("paid Responses request introduced") if preflight_run.include?("/v1/responses")
abort("shell tracing would expose secrets") if preflight_run.include?("set -x")

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

echo 'test_iscy_codex_runtime: OK'
