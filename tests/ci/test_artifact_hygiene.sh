#!/usr/bin/env bash
set -Eeuo pipefail

export LC_ALL=C
umask 077

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
validator="$repo_root/scripts/prepare_ci_artifacts.sh"
workflow="$repo_root/.github/workflows/ci.yml"
visual_config="$repo_root/tests/visual/playwright.config.js"
visual_spec="$repo_root/tests/visual/specs/iscy-visual.spec.js"
visual_runner="$repo_root/scripts/run_visual_regression.sh"
test_parent="${TMPDIR:-/tmp}"
test_root="$(mktemp -d "$test_parent/iscy-artifact-hygiene-test.XXXXXX")"
expected_commit='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
workspace_counter=0
passed=0
skipped=0

die() {
    printf 'ARTIFACT_HYGIENE_TEST_ERROR[%s]\n' "$1" >&2
    exit 1
}

cleanup() {
    local exit_code=$?
    trap - EXIT INT TERM HUP
    set +e
    if [[ "$test_root" == "$test_parent"/iscy-artifact-hygiene-test.* \
        && -d "$test_root" && ! -L "$test_root" ]]; then
        rm -rf -- "$test_root"
    fi
    exit "$exit_code"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

new_workspace() {
    local label="$1"
    workspace_counter=$((workspace_counter + 1))
    current_workspace="$test_root/${workspace_counter}-${label}"
    install -d -m 0700 "$current_workspace"
    install -d -m 0700 "$current_workspace/raw"
    current_raw="$current_workspace/raw"
    current_staging="$current_workspace/staging"
}

write_performance_fixture() {
    local raw_root="$1"
    cat >"$raw_root/performance-smoke.json" <<'JSON'
{
  "schema_version": 1,
  "generated_at": "2026-07-30T12:00:00Z",
  "environment": "synthetic-postgresql16-minio-two-instance",
  "concurrency": 4,
  "total_requests": 10,
  "duration_ms": 1000,
  "throughput_per_second": 10,
  "timeout_count": 0,
  "database_connection_errors": 0,
  "categories": [
    {"name":"health","requests":2,"successes":2,"errors":0,"p50_ms":10,"p95_ms":20,"p99_ms":25,"max_ms":30,"p95_budget_ms":500,"budget_passed":true},
    {"name":"read","requests":2,"successes":2,"errors":0,"p50_ms":20,"p95_ms":30,"p99_ms":35,"max_ms":40,"p95_budget_ms":1000,"budget_passed":true},
    {"name":"review","requests":2,"successes":2,"errors":0,"p50_ms":30,"p95_ms":40,"p99_ms":45,"max_ms":50,"p95_budget_ms":2500,"budget_passed":true},
    {"name":"write","requests":2,"successes":2,"errors":0,"p50_ms":40,"p95_ms":50,"p99_ms":55,"max_ms":60,"p95_budget_ms":2000,"budget_passed":true},
    {"name":"object_storage","requests":2,"successes":2,"errors":0,"p50_ms":50,"p95_ms":60,"p99_ms":65,"max_ms":70,"p95_budget_ms":2500,"budget_passed":true}
  ],
  "contains_personal_data": false,
  "contains_secrets": false
}
JSON
    chmod 600 "$raw_root/performance-smoke.json"
}

write_visual_fixture() {
    local raw_root="$1"
    local outcome="$2"
    local with_diff="${3:-0}"
    local status passed failed diff_json
    if [[ "$outcome" == 'success' ]]; then
        status='passed'
        passed=1
        failed=0
        diff_json='[]'
    else
        status='failed'
        passed=0
        failed=1
        if [[ "$with_diff" == '1' ]]; then
            diff_json='["diffs/desktop-1440-login-diff.png"]'
        else
            diff_json='[]'
        fi
    fi
    jq --null-input \
        --arg status "$status" \
        --argjson passed "$passed" \
        --argjson failed "$failed" \
        --argjson diffs "$diff_json" \
        --arg commit "$expected_commit" \
        '{
          schema_version: 1,
          overall_status: (if $failed == 0 then "passed" else "failed" end),
          total_tests: 1,
          passed: $passed,
          failed: $failed,
          skipped: 0,
          tests: [{
            project_name: "desktop-1440",
            title: "login",
            test_id: "desktop-1440::login",
            status: $status,
            duration_ms: 100,
            diff_files: $diffs
          }],
          commit_sha: $commit,
          synthetic_test_data: true,
          contains_secrets: false,
          contains_personal_data: false
        }' >"$raw_root/visual-summary-source.json"
    chmod 600 "$raw_root/visual-summary-source.json"
    if [[ "$with_diff" == '1' ]]; then
        install -d -m 0700 "$raw_root/diffs"
        printf '%s' \
            'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=' \
            | base64 --decode >"$raw_root/diffs/desktop-1440-login-diff.png"
        chmod 600 "$raw_root/diffs/desktop-1440-login-diff.png"
    fi
}

run_validator() {
    local type="$1"
    local status="$2"
    "$validator" \
        --type "$type" \
        --raw-root "$current_raw" \
        --output-root "$current_staging" \
        --test-status "$status" \
        --expected-commit "$expected_commit"
}

assert_no_validator_temps() {
    local workspace="$1"
    if find -P "$workspace" -maxdepth 1 \
        \( -name '.ci-artifact-candidate.*' \
        -o -name '.ci-artifact-inventory-*' \
        -o -name '.ci-artifact-test-*' \) -print -quit | grep -q .; then
        die temporary_file_left
    fi
}

assert_failure_state() {
    local output_file="$1"
    local secret_value="${2:-}"
    [[ ! -e "$current_staging" && ! -L "$current_staging" ]] \
        || die staging_left_after_failure
    [[ ! -e "$current_raw" && ! -L "$current_raw" ]] \
        || die raw_left_after_failure
    assert_no_validator_temps "$current_workspace"
    if [[ -n "$secret_value" ]] && grep -Fq -- "$secret_value" "$output_file"; then
        die sensitive_value_logged
    fi
    rm -f -- "$output_file"
}

expect_current_failure() {
    local type="$1"
    local status="$2"
    local injection="${3:-}"
    local secret_value="${4:-}"
    local output_file="$current_workspace/validator-output.txt"
    local exit_code
    set +e
    ISCY_TEST_CI_ARTIFACT_FAIL_AT="$injection" \
        run_validator "$type" "$status" >"$output_file" 2>&1
    exit_code=$?
    set -e
    ((exit_code != 0)) || die expected_failure_missing
    assert_failure_state "$output_file" "$secret_value"
    passed=$((passed + 1))
}

new_workspace performance-success
write_performance_fixture "$current_raw"
run_validator performance success >/dev/null
[[ ! -e "$current_raw" ]] || die performance_raw_not_removed
[[ "$(find -P "$current_staging" -type f -printf '%P\n' | sort)" == \
    $'artifact-manifest.json\nperformance-smoke.json\nperformance-smoke.md' ]] \
    || die performance_allowlist
jq --exit-status \
    '.files | length == 2
     and all(.[];
       .classification == "synthetic_aggregate_metrics"
       and (.sha256 | test("^[0-9a-f]{64}$")))' \
    "$current_staging/artifact-manifest.json" >/dev/null
grep -Fq '# ISCY Performance-Smoke' "$current_staging/performance-smoke.md"
first_performance_staging="$current_staging"
passed=$((passed + 1))

new_workspace performance-deterministic
write_performance_fixture "$current_raw"
run_validator performance success >/dev/null
diff -r --no-dereference "$first_performance_staging" "$current_staging" >/dev/null \
    || die performance_not_deterministic
passed=$((passed + 1))

new_workspace visual-success
write_visual_fixture "$current_raw" success
run_validator visual success >/dev/null
[[ "$(find -P "$current_staging" -type f -printf '%P\n' | sort)" == \
    $'artifact-manifest.json\nvisual-summary.json' ]] || die visual_allowlist
first_visual_staging="$current_staging"
passed=$((passed + 1))

new_workspace visual-deterministic
write_visual_fixture "$current_raw" success
run_validator visual success >/dev/null
diff -r --no-dereference "$first_visual_staging" "$current_staging" >/dev/null \
    || die visual_not_deterministic
passed=$((passed + 1))

new_workspace visual-diff
write_visual_fixture "$current_raw" failure 1
run_validator visual failure >/dev/null
[[ -f "$current_staging/diffs/desktop-1440-login-diff.png" ]] \
    || die visual_diff_missing
[[ "$(find -P "$current_staging" -type f -printf '%P\n' | sort)" == \
    $'artifact-manifest.json\ndiffs/desktop-1440-login-diff.png\nvisual-summary.json' ]] \
    || die visual_diff_allowlist
passed=$((passed + 1))

new_workspace symlink
write_performance_fixture "$current_raw"
ln -s performance-smoke.json "$current_raw/linked.json"
expect_current_failure performance success

new_workspace hardlink
write_performance_fixture "$current_raw"
printf 'synthetic fixture\n' >"$current_workspace/outside.txt"
chmod 600 "$current_workspace/outside.txt"
ln "$current_workspace/outside.txt" "$current_raw/linked.txt"
expect_current_failure performance success

new_workspace fifo
write_performance_fixture "$current_raw"
mkfifo -m 600 "$current_raw/result.pipe"
expect_current_failure performance success

new_workspace socket
write_performance_fixture "$current_raw"
perl -MIO::Socket::UNIX -MSocket=SOCK_STREAM \
    -e '$socket = IO::Socket::UNIX->new(Type => SOCK_STREAM, Local => shift, Listen => 1) or die; sleep 30' \
    "$current_raw/result.sock" &
socket_pid=$!
for _ in $(seq 1 100); do
    [[ -S "$current_raw/result.sock" ]] && break
    sleep 0.01
done
[[ -S "$current_raw/result.sock" ]] || die socket_fixture
expect_current_failure performance success
kill "$socket_pid" >/dev/null 2>&1 || true
wait "$socket_pid" 2>/dev/null || true

new_workspace device
write_performance_fixture "$current_raw"
if mknod "$current_raw/result.device" c 1 3 >/dev/null 2>&1; then
    chmod 600 "$current_raw/result.device"
    expect_current_failure performance success
else
    skipped=$((skipped + 1))
    rm -rf -- "$current_workspace"
fi

for unexpected_name in \
    '.hidden' \
    'unexpected.txt' \
    'trace.zip' \
    'session.cookies' \
    'storage-state.json' \
    'backend.log' \
    'runtime.sqlite3' \
    '.env'; do
    new_workspace unexpected-file
    write_performance_fixture "$current_raw"
    printf 'synthetic fixture\n' >"$current_raw/$unexpected_name"
    chmod 600 "$current_raw/$unexpected_name"
    expect_current_failure performance success
done

new_workspace browser-profile
write_performance_fixture "$current_raw"
install -d -m 0700 "$current_raw/browser-profile"
printf 'synthetic fixture\n' >"$current_raw/browser-profile/state"
chmod 600 "$current_raw/browser-profile/state"
expect_current_failure performance success

new_workspace renamed-zip
write_visual_fixture "$current_raw" failure 1
printf 'PK\003\004synthetic' >"$current_raw/diffs/desktop-1440-login-diff.png"
chmod 600 "$current_raw/diffs/desktop-1440-login-diff.png"
expect_current_failure visual failure

new_workspace invalid-png
write_visual_fixture "$current_raw" failure
install -d -m 0700 "$current_raw/diffs"
printf 'not a png\n' >"$current_raw/diffs/desktop-1440-login-diff.png"
chmod 600 "$current_raw/diffs/desktop-1440-login-diff.png"
jq '.tests[0].diff_files = ["diffs/desktop-1440-login-diff.png"]' \
    "$current_raw/visual-summary-source.json" \
    >"$current_raw/summary.tmp"
mv "$current_raw/summary.tmp" "$current_raw/visual-summary-source.json"
chmod 600 "$current_raw/visual-summary-source.json"
expect_current_failure visual failure

new_workspace png-trailing-container
write_visual_fixture "$current_raw" failure 1
printf 'PK\003\004synthetic trailing container' \
    >>"$current_raw/diffs/desktop-1440-login-diff.png"
expect_current_failure visual failure

new_workspace visual-unexpected-raw
write_visual_fixture "$current_raw" success
printf 'synthetic fixture\n' >"$current_raw/trace.zip"
chmod 600 "$current_raw/trace.zip"
expect_current_failure visual success

for marker_case in private-key github-token authorization cookie database-url \
    absolute-path external-url email-address; do
    new_workspace "marker-$marker_case"
    write_visual_fixture "$current_raw" success
    case "$marker_case" in
        private-key) marker='-----BEGIN PRIVATE'' KEY-----' ;;
        github-token) marker='ghp_''ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890' ;;
        authorization) marker='Authorization: Bearer synthetic-value' ;;
        cookie) marker='Set-Cookie: synthetic=value' ;;
        database-url) marker='postgresql://synthetic.invalid/db' ;;
        absolute-path) marker='/home/synthetic/path' ;;
        external-url) marker='https://invalid.example/path' ;;
        email-address) marker='synthetic@example.invalid' ;;
    esac
    jq --arg marker "$marker" '.tests[0].title = $marker' \
        "$current_raw/visual-summary-source.json" \
        >"$current_raw/summary.tmp"
    mv "$current_raw/summary.tmp" "$current_raw/visual-summary-source.json"
    chmod 600 "$current_raw/visual-summary-source.json"
    expect_current_failure visual success '' "$marker"
done

new_workspace oversized
write_performance_fixture "$current_raw"
truncate -s 1048577 "$current_raw/performance-smoke.json"
expect_current_failure performance success

new_workspace too-many-files
write_visual_fixture "$current_raw" success
install -d -m 0700 "$current_raw/diffs"
for index in $(seq 1 51); do
    printf 'x' >"$current_raw/diffs/file-$index-diff.png"
    chmod 600 "$current_raw/diffs/file-$index-diff.png"
done
expect_current_failure visual success

new_workspace unknown-type
write_performance_fixture "$current_raw"
expect_current_failure unknown success

new_workspace identical-roots
write_performance_fixture "$current_raw"
current_staging="$current_raw"
output_file="$current_workspace/validator-output.txt"
set +e
"$validator" --type performance --raw-root "$current_raw" \
    --output-root "$current_staging" --test-status success \
    --expected-commit "$expected_commit" >"$output_file" 2>&1
exit_code=$?
set -e
((exit_code != 0)) || die identical_roots_accepted
rm -rf -- "$current_workspace"
passed=$((passed + 1))

new_workspace output-inside-raw
write_performance_fixture "$current_raw"
current_staging="$current_raw/staging"
set +e
run_validator performance success >/dev/null 2>&1
exit_code=$?
set -e
((exit_code != 0)) || die output_inside_raw_accepted
rm -rf -- "$current_workspace"
passed=$((passed + 1))

parent_workspace="$test_root/raw-inside-output"
install -d -m 0700 "$parent_workspace"
install -d -m 0700 "$parent_workspace/output"
install -d -m 0700 "$parent_workspace/output/raw"
current_workspace="$parent_workspace"
current_raw="$parent_workspace/output/raw"
current_staging="$parent_workspace/output"
write_performance_fixture "$current_raw"
set +e
run_validator performance success >/dev/null 2>&1
exit_code=$?
set -e
((exit_code != 0)) || die raw_inside_output_accepted
rm -rf -- "$parent_workspace"
passed=$((passed + 1))

new_workspace traversal
write_performance_fixture "$current_raw"
canonical_raw="$current_raw"
current_raw="$current_workspace/raw/../raw"
set +e
run_validator performance success >/dev/null 2>&1
exit_code=$?
set -e
((exit_code != 0)) || die traversal_accepted
current_raw="$canonical_raw"
rm -rf -- "$current_workspace"
passed=$((passed + 1))

new_workspace injected-before
write_performance_fixture "$current_raw"
expect_current_failure performance success before_validation

new_workspace injected-between
write_performance_fixture "$current_raw"
expect_current_failure performance success between_validation_and_publish

new_workspace injected-after
write_performance_fixture "$current_raw"
expect_current_failure performance success after_publish

new_workspace staging-symlink-after-publish
write_performance_fixture "$current_raw"
output_file="$current_workspace/validator-output.txt"
ISCY_TEST_CI_ARTIFACT_FAIL_AT=wait_after_publish \
    run_validator performance success >"$output_file" 2>&1 &
validator_pid=$!
for _ in $(seq 1 500); do
    [[ -e "$current_workspace/.ci-artifact-test-ready" ]] && break
    kill -0 "$validator_pid" >/dev/null 2>&1 || break
    sleep 0.01
done
[[ -e "$current_workspace/.ci-artifact-test-ready" ]] \
    || die staging_symlink_sync
ln -s performance-smoke.json "$current_staging/unexpected.json"
: >"$current_workspace/.ci-artifact-test-continue"
set +e
wait "$validator_pid"
exit_code=$?
set -e
((exit_code != 0)) || die staging_symlink_accepted
assert_failure_state "$output_file"
passed=$((passed + 1))

new_workspace signal-after-publish
write_performance_fixture "$current_raw"
output_file="$current_workspace/validator-output.txt"
ISCY_TEST_CI_ARTIFACT_FAIL_AT=wait_after_publish \
    run_validator performance success >"$output_file" 2>&1 &
validator_pid=$!
for _ in $(seq 1 500); do
    [[ -e "$current_workspace/.ci-artifact-test-ready" ]] && break
    kill -0 "$validator_pid" >/dev/null 2>&1 || break
    sleep 0.01
done
[[ -e "$current_workspace/.ci-artifact-test-ready" ]] \
    || die signal_after_publish_sync
kill -TERM "$validator_pid"
set +e
wait "$validator_pid"
exit_code=$?
set -e
((exit_code != 0)) || die signal_after_publish_accepted
assert_failure_state "$output_file"
passed=$((passed + 1))

for signal_point in \
    signal_int_during_processing \
    signal_term_during_processing \
    signal_hup_during_processing; do
    new_workspace signal
    write_performance_fixture "$current_raw"
    expect_current_failure performance success "$signal_point"
done

new_workspace unknown-injection
write_performance_fixture "$current_raw"
expect_current_failure performance success unsupported-test-value

new_workspace unknown-option
write_performance_fixture "$current_raw"
output_file="$current_workspace/validator-output.txt"
set +e
"$validator" --type performance --raw-root "$current_raw" \
    --output-root "$current_staging" --test-status success \
    --expected-commit "$expected_commit" --unsupported-option \
    >"$output_file" 2>&1
exit_code=$?
set -e
((exit_code != 0)) || die unknown_option_accepted
assert_failure_state "$output_file"
passed=$((passed + 1))

new_workspace source-change
write_performance_fixture "$current_raw"
output_file="$current_workspace/validator-output.txt"
ISCY_TEST_CI_ARTIFACT_FAIL_AT=wait_after_validation \
    run_validator performance success >"$output_file" 2>&1 &
validator_pid=$!
for _ in $(seq 1 500); do
    [[ -e "$current_workspace/.ci-artifact-test-ready" ]] && break
    kill -0 "$validator_pid" >/dev/null 2>&1 || break
    sleep 0.01
done
[[ -e "$current_workspace/.ci-artifact-test-ready" ]] || die source_change_sync
printf ' ' >>"$current_raw/performance-smoke.json"
: >"$current_workspace/.ci-artifact-test-continue"
set +e
wait "$validator_pid"
exit_code=$?
set -e
((exit_code != 0)) || die source_change_accepted
assert_failure_state "$output_file"
passed=$((passed + 1))

trusted_condition="github.event.pull_request.head.repo.full_name == github.repository"
[[ "$(grep -Fc "$trusted_condition" "$workflow")" -ge 4 ]] \
    || die fork_guard_missing
[[ "$(grep -Fc "steps.performance_hygiene.outcome == 'success'" "$workflow")" == '1' ]] \
    || die performance_gate_missing
[[ "$(grep -Fc "steps.visual_hygiene.outcome == 'success'" "$workflow")" == '1' ]] \
    || die visual_gate_missing
if grep -Eq 'pull_request_target|runs-on:[[:space:]]*self-hosted' "$workflow"; then
    die prohibited_workflow_trigger
fi
if grep -Eq 'path:[[:space:]]*artifacts/' "$workflow" \
    || grep -Fq 'path: ./' "$workflow" \
    || grep -Fq 'path: **' "$workflow"; then
    die raw_upload_path
fi
upload_v7='uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1'
[[ "$(grep -Fc "$upload_v7" "$workflow")" == '2' ]] || die upload_action_pin
[[ "$(grep -Fc 'if-no-files-found: error' "$workflow")" == '2' ]] \
    || die upload_missing_file_policy
[[ "$(grep -Fc 'include-hidden-files: false' "$workflow")" == '2' ]] \
    || die upload_hidden_file_policy
[[ "$(grep -Fc 'retention-days: 7' "$workflow")" == '2' ]] \
    || die upload_retention_policy
if grep -Eq '^[[:space:]]+overwrite:' "$workflow"; then
    die upload_overwrite_enabled
fi
checkout_count="$(grep -Ec 'uses: actions/checkout@[0-9a-f]{40}' "$workflow")"
credential_guard_count="$(grep -Fc 'persist-credentials: false' "$workflow")"
[[ "$checkout_count" -gt 0 && "$checkout_count" == "$credential_guard_count" ]] \
    || die checkout_credentials
while IFS= read -r action_reference; do
    if [[ "$action_reference" != ./* \
        && ! "$action_reference" =~ @[0-9a-f]{40}$ ]]; then
        die action_not_sha_pinned
    fi
done < <(
    sed -n 's/^[[:space:]]*-[[:space:]]*uses:[[:space:]]*//p' "$workflow" \
        | sed 's/[[:space:]]*#.*$//'
)
grep -Fq 'requestOrigin === "http://127.0.0.1:19200"' "$visual_spec" \
    || die browser_origin_allowlist
grep -Fq 'VISUAL_NETWORK_ERROR[external_request_blocked]' "$visual_spec" \
    || die browser_external_request_gate
grep -Fq 'trace: "off"' "$visual_config" || die playwright_trace_enabled
grep -Fq 'video: "off"' "$visual_config" || die playwright_video_enabled
grep -Fq 'screenshot: "off"' "$visual_config" || die playwright_raw_screenshot_enabled
for isolated_variable in TMPDIR XDG_RUNTIME_DIR XDG_CACHE_HOME; do
    grep -Fq "export $isolated_variable=" "$visual_runner" \
        || die browser_environment_isolation
done
grep -Fq "unset \"\$sensitive_variable\"" "$visual_runner" \
    || die inherited_secret_environment
passed=$((passed + 1))

printf 'ARTIFACT_HYGIENE_TEST_OK passed=%s skipped=%s\n' "$passed" "$skipped"
