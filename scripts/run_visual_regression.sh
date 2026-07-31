#!/usr/bin/env bash
set -Eeuo pipefail

export LC_ALL=C
umask 077

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
workspace_root=''
runtime_root=''
raw_root=''
backend_pid=''
owns_workspace=0
visual_temp_parent=''

fail() {
    printf 'VISUAL_RUN_ERROR[%s]\n' "$1" >&2
    exit 1
}

cleanup() {
    local exit_code=$?
    trap - EXIT ERR INT TERM HUP
    set +e
    if [[ -n "$backend_pid" ]]; then
        kill -TERM "$backend_pid" >/dev/null 2>&1
        wait "$backend_pid" 2>/dev/null
    fi
    if [[ -n "$runtime_root" \
        && "$runtime_root" == "$workspace_root/runtime" \
        && -d "$runtime_root" && ! -L "$runtime_root" ]]; then
        rm -rf -- "$runtime_root"
    fi
    if [[ -e "$runtime_root" || -L "$runtime_root" ]]; then
        printf 'VISUAL_RUN_ERROR[runtime_cleanup]\n' >&2
        exit_code=1
    fi
    if ((owns_workspace == 1)) \
        && [[ -n "$workspace_root" \
            && "$workspace_root" == "${visual_temp_parent%/}"/iscy-visual-artifacts.* \
            && -d "$workspace_root" && ! -L "$workspace_root" ]]; then
        rm -rf -- "$workspace_root"
        if [[ -e "$workspace_root" || -L "$workspace_root" ]]; then
            printf 'VISUAL_RUN_ERROR[workspace_cleanup]\n' >&2
            exit_code=1
        fi
    fi
    exit "$exit_code"
}

on_error() {
    local exit_code=$?
    trap - ERR
    exit "$exit_code"
}

on_signal() {
    local exit_code="$1"
    trap - INT TERM HUP
    exit "$exit_code"
}

trap cleanup EXIT
trap on_error ERR
trap 'on_signal 130' INT
trap 'on_signal 143' TERM
trap 'on_signal 129' HUP

visual_temp_parent="${RUNNER_TEMP:-${XDG_RUNTIME_DIR:-/tmp}}"
[[ -d "$visual_temp_parent" && ! -L "$visual_temp_parent" ]] \
    || fail temp_parent_type
visual_temp_parent="$(realpath -e -- "$visual_temp_parent")"

if [[ -n "${ISCY_VISUAL_WORKSPACE_ROOT:-}" ]]; then
    workspace_root="$ISCY_VISUAL_WORKSPACE_ROOT"
    [[ "$workspace_root" == /* && -d "$workspace_root" && ! -L "$workspace_root" ]] \
        || fail workspace_type
    [[ "$(realpath -e -- "$workspace_root")" == "$workspace_root" ]] \
        || fail workspace_not_canonical
    [[ "$workspace_root" == "$visual_temp_parent"/* ]] || fail workspace_boundary
    [[ "$(id -u)" == "$(stat -c '%u' -- "$workspace_root")" ]] \
        || fail workspace_owner
    [[ "$(stat -c '%a' -- "$workspace_root")" == '700' ]] \
        || fail workspace_permissions
else
    workspace_root="$(mktemp -d "$visual_temp_parent/iscy-visual-artifacts.XXXXXX")"
    chmod 700 "$workspace_root"
    owns_workspace=1
fi

raw_root="${ISCY_VISUAL_RAW_ROOT:-$workspace_root/raw}"
[[ "$raw_root" == "$workspace_root/raw" ]] || fail raw_root_boundary
if [[ -e "$raw_root" || -L "$raw_root" ]]; then
    [[ -d "$raw_root" && ! -L "$raw_root" ]] || fail raw_root_type
    [[ "$(realpath -e -- "$raw_root")" == "$raw_root" ]] || fail raw_root_not_canonical
    [[ "$(stat -c '%a' -- "$raw_root")" == '700' ]] || fail raw_root_permissions
    [[ -z "$(find -P "$raw_root" -mindepth 1 -print -quit)" ]] || fail raw_root_not_empty
else
    install -d -m 0700 "$raw_root"
fi

runtime_root="$workspace_root/runtime"
[[ ! -e "$runtime_root" && ! -L "$runtime_root" ]] || fail runtime_already_exists
database_root="$runtime_root/database"
media_root="$runtime_root/media"
backend_log_root="$runtime_root/backend-log"
browser_tmp_root="$runtime_root/browser-tmp"
xdg_cache_root="$runtime_root/xdg-cache"
xdg_runtime_root="$runtime_root/xdg-runtime"
playwright_output_root="$runtime_root/playwright-output"
for private_directory in \
    "$runtime_root" \
    "$database_root" \
    "$media_root" \
    "$backend_log_root" \
    "$browser_tmp_root" \
    "$xdg_cache_root" \
    "$xdg_runtime_root" \
    "$playwright_output_root"; do
    install -d -m 0700 "$private_directory"
done

case "${ISCY_TEST_VISUAL_FORCE_DIFF:-0}" in
    0 | 1) ;;
    *) fail unknown_test_failure_point ;;
esac
case "${ISCY_UPDATE_VISUAL_BASELINES:-0}" in
    0 | 1) ;;
    *) fail update_baselines_value ;;
esac
[[ "${ISCY_VISUAL_BASE_URL:-http://127.0.0.1:19200}" == \
    'http://127.0.0.1:19200' ]] || fail base_url

for sensitive_variable in \
    GITHUB_TOKEN GH_TOKEN ACTIONS_RUNTIME_TOKEN ACTIONS_ID_TOKEN_REQUEST_TOKEN \
    ACTIONS_ID_TOKEN_REQUEST_URL AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY \
    AWS_SESSION_TOKEN AZURE_CLIENT_SECRET GOOGLE_APPLICATION_CREDENTIALS \
    DATABASE_URL COOKIE SESSION SESSION_ID AUTHORIZATION HTTP_AUTHORIZATION \
    ISCY_S3_ACCESS_KEY ISCY_S3_SECRET_KEY OPENAI_API_KEY; do
    unset "$sensitive_variable"
done
unset HTTP_PROXY HTTPS_PROXY ALL_PROXY http_proxy https_proxy all_proxy

db_path="$database_root/iscy-visual.sqlite3"
log_file="$backend_log_root/iscy-visual.log"
export DATABASE_URL="sqlite:////${db_path#/}"
export ISCY_MEDIA_ROOT="$media_root"
export RUST_BACKEND_BIND='127.0.0.1:19200'
export ISCY_VISUAL_BASE_URL='http://127.0.0.1:19200'
export ISCY_AGENT_NOTIFICATION_INTERVAL_SECONDS=0
export TZ='Europe/Berlin'
export LANG='de_DE.UTF-8'
export LC_ALL='de_DE.UTF-8'
export TMPDIR="$browser_tmp_root"
export XDG_RUNTIME_DIR="$xdg_runtime_root"
export XDG_CACHE_HOME="$xdg_cache_root"
export NO_PROXY='127.0.0.1,localhost'
export no_proxy='127.0.0.1,localhost'
export ISCY_VISUAL_RAW_ROOT="$raw_root"
export ISCY_PLAYWRIGHT_OUTPUT_ROOT="$playwright_output_root"
export ISCY_EXPECTED_COMMIT_SHA="${ISCY_EXPECTED_COMMIT_SHA:-$(git -C "$ROOT_DIR" rev-parse HEAD)}"
[[ "$ISCY_EXPECTED_COMMIT_SHA" =~ ^[0-9a-f]{40}$ ]] || fail commit_sha_format

cargo run --locked --manifest-path "$ROOT_DIR/rust/iscy-backend/Cargo.toml" \
    --bin iscy-backend -- init-demo >/dev/null
cargo run --locked --manifest-path "$ROOT_DIR/rust/iscy-backend/Cargo.toml" \
    --bin iscy-backend >"$log_file" 2>&1 &
backend_pid=$!

backend_ready=0
for _ in $(seq 1 60); do
    if curl --fail --silent --show-error \
        "$ISCY_VISUAL_BASE_URL/health/ready" >/dev/null 2>&1; then
        backend_ready=1
        break
    fi
    kill -0 "$backend_pid" >/dev/null 2>&1 || fail backend_stopped
    sleep 1
done
((backend_ready == 1)) || fail backend_timeout

playwright_args=(--config "$ROOT_DIR/tests/visual/playwright.config.js")
if [[ "${ISCY_UPDATE_VISUAL_BASELINES:-0}" == '1' ]]; then
    playwright_args+=(--update-snapshots)
fi

set +e
playwright test "${playwright_args[@]}"
playwright_status=$?
set -e

[[ -f "$raw_root/visual-summary-source.json" \
    && ! -L "$raw_root/visual-summary-source.json" ]] || fail summary_missing

while IFS= read -r -d '' playwright_path; do
    relative_path="${playwright_path#"$playwright_output_root"/}"
    if [[ -L "$playwright_path" ]]; then
        fail playwright_symlink
    elif [[ -d "$playwright_path" ]]; then
        [[ "$(stat -c '%a' -- "$playwright_path")" == '700' ]] \
            || fail playwright_directory_permissions
    elif [[ -f "$playwright_path" ]]; then
        [[ "$(stat -c '%h' -- "$playwright_path")" == '1' ]] \
            || fail playwright_hardlink
        case "$(basename -- "$relative_path")" in
            .last-run.json | *-actual.png | *-expected.png | *-diff.png) ;;
            *) fail unexpected_playwright_output ;;
        esac
    else
        fail playwright_special_file
    fi
done < <(find -P "$playwright_output_root" -mindepth 1 -print0)

if [[ "${ISCY_TEST_VISUAL_FORCE_DIFF:-0}" == '1' ]]; then
    ((playwright_status != 0)) || fail forced_diff_not_detected
else
    ((playwright_status == 0)) || exit "$playwright_status"
fi

if ((playwright_status == 0)); then
    printf 'ISCY Visual-Regression-Test OK\n'
else
    printf 'ISCY Visual-Regression-Test erzeugte erwarteten synthetischen Diff.\n'
    exit "$playwright_status"
fi
