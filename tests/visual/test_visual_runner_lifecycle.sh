#!/usr/bin/env bash
set -Eeuo pipefail

export LC_ALL=C
umask 077

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
runner="$repo_root/scripts/run_visual_regression.sh"
test_parent="${TMPDIR:-/tmp}"
test_root="$(mktemp -d "$test_parent/iscy-visual-runner-lifecycle-test.XXXXXX")"
fake_bin="$test_root/bin"
runner_temp="$test_root/runner-temp"
passed=0

die() {
    printf 'VISUAL_RUNNER_LIFECYCLE_TEST_ERROR[%s]\n' "$1" >&2
    exit 1
}

cleanup() {
    local exit_code=$?
    trap - EXIT INT TERM HUP
    set +e
    if [[ "$test_root" == "$test_parent"/iscy-visual-runner-lifecycle-test.* \
        && -d "$test_root" && ! -L "$test_root" ]]; then
        rm -rf -- "$test_root"
    fi
    exit "$exit_code"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

install -d -m 0700 "$fake_bin" "$runner_temp"

cat >"$fake_bin/visual-contract.sh" <<'STUB'
fail_stub() {
    printf 'VISUAL_LIFECYCLE_STUB_ERROR[%s]\n' "$1" >&2
    exit 97
}

assert_visual_contract() {
    local phase="$1"
    local runtime_root workspace_root
    [[ -n "${ISCY_MEDIA_ROOT:-}" && "$ISCY_MEDIA_ROOT" == /* ]] \
        || fail_stub media_root_missing
    runtime_root="$(dirname -- "$ISCY_MEDIA_ROOT")"
    workspace_root="$(dirname -- "$runtime_root")"
    [[ "$runtime_root" == "$workspace_root/runtime" \
        && "$ISCY_MEDIA_ROOT" == "$runtime_root/media" ]] \
        || fail_stub media_root_boundary
    [[ "$workspace_root" == "$RUNNER_TEMP"/iscy-visual-artifacts.* ]] \
        || fail_stub workspace_boundary
    [[ -d "$runtime_root" && ! -L "$runtime_root" \
        && "$(realpath -e -- "$runtime_root")" == "$runtime_root" ]] \
        || fail_stub runtime_root_type
    [[ "$(id -u)" == "$(stat -c '%u' -- "$runtime_root")" ]] \
        || fail_stub runtime_root_owner
    [[ "$(stat -c '%a' -- "$runtime_root")" == '700' ]] \
        || fail_stub runtime_root_permissions
    [[ ! -e "$ISCY_MEDIA_ROOT" && ! -L "$ISCY_MEDIA_ROOT" ]] \
        || fail_stub media_root_exists
    [[ "$TMPDIR" == "$runtime_root/browser-tmp" \
        && "$XDG_CACHE_HOME" == "$runtime_root/xdg-cache" \
        && "$XDG_RUNTIME_DIR" == "$runtime_root/xdg-runtime" \
        && "$ISCY_PLAYWRIGHT_OUTPUT_ROOT" == "$runtime_root/playwright-output" ]] \
        || fail_stub runtime_isolation
    [[ "$ISCY_VISUAL_RAW_ROOT" == "$workspace_root/raw" \
        && -d "$ISCY_VISUAL_RAW_ROOT" && ! -L "$ISCY_VISUAL_RAW_ROOT" ]] \
        || fail_stub raw_root_boundary
    printf '%s\n' "$ISCY_MEDIA_ROOT" \
        >"$ISCY_VISUAL_LIFECYCLE_TEST_MARKERS/$phase-media-root"
}
STUB
chmod 600 "$fake_bin/visual-contract.sh"

cat >"$fake_bin/cargo" <<'STUB'
#!/usr/bin/env bash
set -Eeuo pipefail

# shellcheck source=/dev/null
source "$ISCY_VISUAL_LIFECYCLE_TEST_CONTRACT"

last_argument="${!#}"
if [[ "$last_argument" == 'init-demo' ]]; then
    assert_visual_contract init
    case "${ISCY_VISUAL_LIFECYCLE_TEST_CREATE_AT:-none}" in
        init-directory)
            install -d -m 0700 "$ISCY_MEDIA_ROOT"
            ;;
        init-symlink)
            ln -s "$ISCY_VISUAL_LIFECYCLE_TEST_MARKERS/nonexistent-target" \
                "$ISCY_MEDIA_ROOT"
            ;;
    esac
    exit 0
fi

assert_visual_contract backend
if [[ "${ISCY_VISUAL_LIFECYCLE_TEST_CREATE_AT:-none}" == 'backend' ]]; then
    install -d -m 0700 "$ISCY_MEDIA_ROOT"
fi
printf '%s\n' "$BASHPID" >"$ISCY_VISUAL_LIFECYCLE_TEST_MARKERS/backend-pid"
trap 'exit 0' INT TERM HUP
while :; do
    sleep 0.01
done
STUB
chmod 700 "$fake_bin/cargo"

cat >"$fake_bin/curl" <<'STUB'
#!/usr/bin/env bash
set -Eeuo pipefail

for _ in $(seq 1 200); do
    if [[ -f "$ISCY_VISUAL_LIFECYCLE_TEST_MARKERS/backend-pid" ]]; then
        printf '%s\n' "$ISCY_MEDIA_ROOT" \
            >"$ISCY_VISUAL_LIFECYCLE_TEST_MARKERS/ready-media-root"
        exit 0
    fi
    sleep 0.01
done
exit 1
STUB
chmod 700 "$fake_bin/curl"

cat >"$fake_bin/playwright" <<'STUB'
#!/usr/bin/env bash
set -Eeuo pipefail

# shellcheck source=/dev/null
source "$ISCY_VISUAL_LIFECYCLE_TEST_CONTRACT"
[[ "${1:-}" == 'test' ]] || fail_stub playwright_arguments
assert_visual_contract playwright
if [[ "${ISCY_VISUAL_LIFECYCLE_TEST_CREATE_AT:-none}" == 'playwright' ]]; then
    install -d -m 0700 "$ISCY_MEDIA_ROOT"
    printf '%s\n' "$ISCY_MEDIA_ROOT" \
        >"$ISCY_VISUAL_LIFECYCLE_TEST_MARKERS/later-media-root"
fi
printf '{"schema_version":1}\n' \
    >"$ISCY_VISUAL_RAW_ROOT/visual-summary-source.json"
chmod 600 "$ISCY_VISUAL_RAW_ROOT/visual-summary-source.json"
STUB
chmod 700 "$fake_bin/playwright"

assert_runner_cleanup() {
    local marker_root="$1"
    local backend_pid
    if find -P "$runner_temp" -mindepth 1 -print -quit | grep -q .; then
        die runner_workspace_left
    fi
    if [[ -f "$marker_root/backend-pid" ]]; then
        backend_pid="$(<"$marker_root/backend-pid")"
        [[ "$backend_pid" =~ ^[1-9][0-9]*$ ]] || die backend_pid_format
        if kill -0 "$backend_pid" >/dev/null 2>&1; then
            die backend_process_left
        fi
    fi
}

run_runner_case() {
    local case_name="$1"
    local create_at="$2"
    local expected_category="${3:-}"
    local marker_root="$test_root/markers-$case_name"
    local output_file="$test_root/$case_name.output"
    local exit_code
    install -d -m 0700 "$marker_root"

    set +e
    env \
        -u ISCY_VISUAL_WORKSPACE_ROOT \
        -u ISCY_VISUAL_RAW_ROOT \
        -u ISCY_UPDATE_VISUAL_BASELINES \
        -u ISCY_TEST_VISUAL_FORCE_DIFF \
        PATH="$fake_bin:$PATH" \
        RUNNER_TEMP="$runner_temp" \
        ISCY_EXPECTED_COMMIT_SHA='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' \
        ISCY_VISUAL_LIFECYCLE_TEST_CONTRACT="$fake_bin/visual-contract.sh" \
        ISCY_VISUAL_LIFECYCLE_TEST_MARKERS="$marker_root" \
        ISCY_VISUAL_LIFECYCLE_TEST_CREATE_AT="$create_at" \
        "$runner" >"$output_file" 2>&1
    exit_code=$?
    set -e

    if [[ -z "$expected_category" ]]; then
        ((exit_code == 0)) || die "$case_name"
        grep -Fq 'ISCY Visual-Regression-Test OK' "$output_file" \
            || die success_output
        for phase in init backend ready playwright later; do
            [[ -s "$marker_root/$phase-media-root" ]] \
                || die "$phase"_marker_missing
        done
        expected_media_root="$(<"$marker_root/init-media-root")"
        for phase in backend ready playwright later; do
            [[ "$(<"$marker_root/$phase-media-root")" == "$expected_media_root" ]] \
                || die "$phase"_media_root_mismatch
        done
        [[ "$expected_media_root" == \
            "$runner_temp"/iscy-visual-artifacts.*/runtime/media ]] \
            || die media_root_not_private
    else
        ((exit_code != 0)) || die "$case_name"_failure_missing
        grep -Fq "VISUAL_RUN_ERROR[$expected_category]" "$output_file" \
            || die "$case_name"_failure_category
    fi

    assert_runner_cleanup "$marker_root"
    passed=$((passed + 1))
}

run_runner_case normal-lifecycle playwright
run_runner_case init-created-directory init-directory media_root_created_by_init
run_runner_case init-created-symlink init-symlink media_root_created_by_init
run_runner_case backend-created-directory backend media_root_created_by_backend

printf 'VISUAL_RUNNER_LIFECYCLE_TEST_OK passed=%s\n' "$passed"
