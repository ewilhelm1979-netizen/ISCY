#!/usr/bin/env bash
set -Eeuo pipefail

export LC_ALL=C
umask 077

artifact_type=''
raw_root=''
output_root=''
test_status=''
expected_commit=''
parse_error=''
candidate_dir=''
inventory_before=''
inventory_after=''
test_ready_marker=''
test_continue_marker=''
output_created=0
transaction_complete=0
raw_cleanup_allowed=0
workspace_root=''

fail() {
    local category="$1"
    local relative_path="${2:--}"
    printf 'CI_ARTIFACT_ERROR[%s] path=%s\n' "$category" "$relative_path" >&2
    exit 1
}

usage() {
    cat >&2 <<'EOF'
Usage: prepare_ci_artifacts.sh \
  --type performance|visual \
  --raw-root ABSOLUTE_PATH \
  --output-root ABSOLUTE_PATH \
  --test-status success|failure \
  --expected-commit FULL_SHA
EOF
    exit 2
}

while (($#)); do
    case "$1" in
        --type)
            (($# >= 2)) || usage
            artifact_type="$2"
            shift 2
            ;;
        --raw-root)
            (($# >= 2)) || usage
            raw_root="$2"
            shift 2
            ;;
        --output-root)
            (($# >= 2)) || usage
            output_root="$2"
            shift 2
            ;;
        --test-status)
            (($# >= 2)) || usage
            test_status="$2"
            shift 2
            ;;
        --expected-commit)
            (($# >= 2)) || usage
            expected_commit="$2"
            shift 2
            ;;
        *)
            parse_error='unknown_option'
            shift
            ;;
    esac
done

[[ -n "$raw_root" && -n "$output_root" ]] || usage
[[ "$raw_root" == /* && "$output_root" == /* ]] || fail path_not_absolute
[[ "$raw_root" != *$'\n'* && "$output_root" != *$'\n'* ]] || fail path_invalid
[[ "$raw_root" != */../* && "$raw_root" != */.. && "$raw_root" != */./* ]] \
    || fail path_traversal
[[ "$output_root" != */../* && "$output_root" != */.. && "$output_root" != */./* ]] \
    || fail path_traversal
[[ -d "$raw_root" && ! -L "$raw_root" ]] || fail raw_root_type

raw_root_real="$(realpath -e -- "$raw_root")" || fail raw_root_resolution
[[ "$raw_root_real" == "$raw_root" ]] || fail raw_root_not_canonical
workspace_root="$(dirname -- "$raw_root_real")"
workspace_real="$(realpath -e -- "$workspace_root")" || fail workspace_resolution
[[ "$workspace_real" == "$workspace_root" && -d "$workspace_root" && ! -L "$workspace_root" ]] \
    || fail workspace_not_canonical
[[ "$(dirname -- "$output_root")" == "$workspace_root" ]] || fail root_separation
[[ "$(dirname -- "$raw_root_real")" == "$workspace_root" ]] || fail root_separation
[[ "$raw_root_real" != "$output_root" ]] || fail roots_identical
[[ ! -e "$output_root" && ! -L "$output_root" ]] || fail output_already_exists
[[ "$(id -u)" == "$(stat -c '%u' -- "$workspace_root")" ]] || fail workspace_owner
[[ "$(id -u)" == "$(stat -c '%u' -- "$raw_root_real")" ]] || fail raw_root_owner
[[ "$(stat -c '%a' -- "$workspace_root")" == '700' ]] || fail workspace_permissions
[[ "$(stat -c '%a' -- "$raw_root_real")" == '700' ]] || fail raw_root_permissions
[[ "$(basename -- "$raw_root_real")" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,80}$ ]] \
    || fail raw_root_name
[[ "$(basename -- "$output_root")" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,80}$ ]] \
    || fail output_root_name

raw_cleanup_allowed=1

cleanup() {
    local exit_code=$?
    trap - EXIT ERR INT TERM HUP
    set +e

    [[ -z "$test_ready_marker" ]] || rm -f -- "$test_ready_marker"
    [[ -z "$test_continue_marker" ]] || rm -f -- "$test_continue_marker"
    [[ -z "$inventory_before" ]] || rm -f -- "$inventory_before"
    [[ -z "$inventory_after" ]] || rm -f -- "$inventory_after"

    if [[ -n "$candidate_dir" \
        && "$candidate_dir" == "$workspace_root"/.ci-artifact-candidate.* \
        && -d "$candidate_dir" && ! -L "$candidate_dir" ]]; then
        rm -rf -- "$candidate_dir"
    fi

    if ((exit_code != 0 || transaction_complete == 0)) \
        && ((output_created == 1)) \
        && [[ "$output_root" == "$workspace_root"/* \
            && "$(dirname -- "$output_root")" == "$workspace_root" \
            && -d "$output_root" && ! -L "$output_root" ]]; then
        rm -rf -- "$output_root"
    fi

    if ((raw_cleanup_allowed == 1)) \
        && [[ "$raw_root_real" == "$workspace_root"/* \
            && "$(dirname -- "$raw_root_real")" == "$workspace_root" \
            && -d "$raw_root_real" && ! -L "$raw_root_real" ]]; then
        rm -rf -- "$raw_root_real"
    fi
    if [[ -e "$raw_root_real" || -L "$raw_root_real" ]]; then
        printf 'CI_ARTIFACT_ERROR[raw_cleanup] path=-\n' >&2
        exit_code=1
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

[[ -z "$parse_error" ]] || fail "$parse_error"
case "$artifact_type" in
    performance | visual) ;;
    *) fail unknown_artifact_type ;;
esac
case "$test_status" in
    success | failure) ;;
    *) fail unknown_test_status ;;
esac
[[ "$expected_commit" =~ ^[0-9a-f]{40}$ ]] || fail commit_sha_format

# Ausschliesslich fuer Regressionstests. Im Normalbetrieb ist die Variable leer
# und hat keinerlei Wirkung. Unbekannte Werte werden fail-closed abgewiesen.
test_failure_point="${ISCY_TEST_CI_ARTIFACT_FAIL_AT:-}"
case "$test_failure_point" in
    '' | before_validation | wait_after_validation \
        | between_validation_and_publish | wait_after_publish | after_publish \
        | signal_int_during_processing | signal_term_during_processing \
        | signal_hup_during_processing) ;;
    *) fail unknown_test_failure_point ;;
esac

case "$test_failure_point" in
    before_validation) fail injected_before_validation ;;
esac

safe_relative_path() {
    local relative_path="$1"
    [[ -n "$relative_path" ]] || return 1
    [[ "$relative_path" != /* ]] || return 1
    [[ "$relative_path" != *$'\n'* && "$relative_path" != *$'\t'* ]] || return 1
    [[ "$relative_path" != ../* && "$relative_path" != */../* \
        && "$relative_path" != */.. && "$relative_path" != *//* ]] || return 1
    [[ "$relative_path" =~ ^[A-Za-z0-9][A-Za-z0-9._/-]{0,240}$ ]] || return 1
    [[ "/$relative_path" != */.* ]] || return 1
}

validate_raw_tree() {
    local path relative_path link_count mode_decimal
    local file_count=0
    local directory_count=0
    local total_size=0
    local -a entries=()

    mapfile -d '' entries < <(
        find -P "$raw_root_real" -mindepth 1 -print0 | sort -z
    )
    ((${#entries[@]} > 0)) || fail raw_empty

    for path in "${entries[@]}"; do
        relative_path="${path#"$raw_root_real"/}"
        safe_relative_path "$relative_path" || fail raw_path_invalid
        if [[ -L "$path" ]]; then
            fail symlink "$relative_path"
        elif [[ -d "$path" ]]; then
            ((directory_count += 1))
            [[ "$artifact_type" == 'visual' && "$relative_path" == 'diffs' ]] \
                || fail unexpected_directory "$relative_path"
            [[ "$(stat -c '%a' -- "$path")" == '700' ]] \
                || fail directory_permissions "$relative_path"
        elif [[ -f "$path" ]]; then
            ((file_count += 1))
            link_count="$(stat -c '%h' -- "$path")"
            [[ "$link_count" == '1' ]] || fail hardlink "$relative_path"
            mode_decimal=$((8#$(stat -c '%a' -- "$path")))
            (( (mode_decimal & 077) == 0 )) || fail file_permissions "$relative_path"
            total_size=$((total_size + $(stat -c '%s' -- "$path")))
            case "$artifact_type" in
                performance)
                    [[ "$relative_path" == 'performance-smoke.json' ]] \
                        || fail unexpected_file "$relative_path"
                    ;;
                visual)
                    if [[ "$relative_path" == 'visual-summary-source.json' ]]; then
                        :
                    elif [[ "$relative_path" =~ ^diffs/(desktop-1440|laptop-1024)-[a-z0-9][a-z0-9-]{0,100}-diff\.png$ ]]; then
                        case "$relative_path" in
                            *actual* | *expected* | *test-failed* | *screenshot* \
                                | *trace* | *video*)
                                fail prohibited_visual_filename "$relative_path"
                                ;;
                        esac
                    else
                        fail unexpected_file "$relative_path"
                    fi
                    ;;
            esac
        else
            fail special_file "$relative_path"
        fi
    done

    case "$artifact_type" in
        performance)
            ((file_count == 1 && directory_count == 0)) || fail performance_file_count
            ((total_size <= 1048576)) || fail performance_raw_size
            ;;
        visual)
            ((file_count >= 1 && file_count <= 51 && directory_count <= 1)) \
                || fail visual_file_count
            ((total_size <= 27262976)) || fail visual_raw_size
            ;;
    esac
}

write_inventory() {
    local destination="$1"
    local path relative_path
    local -a entries=()
    : >"$destination"
    mapfile -d '' entries < <(
        find -P "$raw_root_real" -mindepth 1 -print0 | sort -z
    )
    for path in "${entries[@]}"; do
        relative_path="${path#"$raw_root_real"/}"
        if [[ -d "$path" && ! -L "$path" ]]; then
            printf 'd\t%s\t%s\t%s\n' \
                "$relative_path" "$(stat -c '%a' -- "$path")" \
                "$(stat -c '%i' -- "$path")" >>"$destination"
        elif [[ -f "$path" && ! -L "$path" ]]; then
            printf 'f\t%s\t%s\t%s\t%s\t%s\n' \
                "$relative_path" "$(stat -c '%a' -- "$path")" \
                "$(stat -c '%s' -- "$path")" "$(stat -c '%i' -- "$path")" \
                "$(sha256sum -- "$path" | cut -d' ' -f1)" >>"$destination"
        else
            fail source_type_changed "$relative_path"
        fi
    done
}

finding_line() {
    local pattern="$1"
    local path="$2"
    local result
    result="$(grep -niE -m 1 -- "$pattern" "$path" 2>/dev/null || true)"
    [[ -n "$result" ]] || return 1
    printf '%s' "${result%%:*}"
}

scan_text_file() {
    local relative_path="$1"
    local path="$2"
    local category pattern line
    local -a scans=(
        'github_token|gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,}'
        'generic_api_key|(api[_-]?key|access[_-]?token)[[:space:]]*[:=][[:space:]]*[^[:space:],}]+'
        'bearer_token|bearer[[:space:]]+[A-Za-z0-9._~+/-]{10,}'
        'authorization_header|authorization[[:space:]]*:'
        'cookie_header|(^|[^A-Za-z])(set-cookie|cookie)[[:space:]]*:'
        'session_identifier|session[_-]?(id|token)[[:space:]]*[:=]'
        'password_assignment|password[[:space:]]*[:=]'
        'private_key|-----BEGIN ([A-Z0-9 ]+ )?PRIVATE KEY-----'
        'pem_content|-----BEGIN (CERTIFICATE|PUBLIC KEY)-----'
        'aws_access_key|AKIA[0-9A-Z]{16}'
        'database_url|(postgres(ql)?|mysql|mariadb|sqlite)://'
        'env_assignment|^[A-Z][A-Z0-9_]{1,63}='
        'home_path|/home/'
        'nix_store_path|/nix/store/'
        'github_workspace_path|/github/workspace/'
        'temporary_path|/tmp/'
        'file_url|file://'
        "windows_user_path|[A-Za-z]:\\\\Users\\\\"
        'external_url|https?://'
        'email_address|[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}'
    )

    for category_pattern in "${scans[@]}"; do
        category="${category_pattern%%|*}"
        pattern="${category_pattern#*|}"
        if line="$(finding_line "$pattern" "$path")"; then
            printf 'CI_ARTIFACT_ERROR[%s] path=%s line=%s\n' \
                "$category" "$relative_path" "$line" >&2
            exit 1
        fi
    done
}

validate_performance_json() {
    local source="$raw_root_real/performance-smoke.json"
    [[ -f "$source" && ! -L "$source" ]] || fail performance_source_missing
    [[ "$(stat -c '%s' -- "$source")" -le 1048576 ]] \
        || fail file_too_large performance-smoke.json

    jq --exit-status '
      def exact_keys($wanted): ((keys | sort) == ($wanted | sort));
      exact_keys([
        "schema_version", "generated_at", "environment", "concurrency",
        "total_requests", "duration_ms", "throughput_per_second",
        "timeout_count", "database_connection_errors", "categories",
        "contains_personal_data", "contains_secrets"
      ])
      and (.schema_version == 1)
      and (.generated_at | type == "string"
        and test("^20[0-9]{2}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"))
      and (.environment == "synthetic-postgresql16-minio-two-instance")
      and (.contains_personal_data == false)
      and (.contains_secrets == false)
      and (.concurrency | type == "number" and floor == . and . >= 1 and . <= 4)
      and (.total_requests | type == "number" and floor == . and . > 0)
      and (.duration_ms | type == "number" and . > 0)
      and (.throughput_per_second | type == "number" and . > 0)
      and (.timeout_count == 0)
      and (.database_connection_errors == 0)
      and (.categories | type == "array" and length == 5)
      and (([.categories[].name] | sort)
        == ["health", "object_storage", "read", "review", "write"])
      and (all(.categories[];
        exact_keys([
          "name", "requests", "successes", "errors", "p50_ms", "p95_ms",
          "p99_ms", "max_ms", "p95_budget_ms", "budget_passed"
        ])
        and (.name | IN("health", "read", "review", "write", "object_storage"))
        and (.requests | type == "number" and floor == . and . > 0)
        and (.successes | type == "number" and floor == . and . >= 0)
        and (.errors == 0)
        and (.successes + .errors == .requests)
        and (.p50_ms | type == "number")
        and (.p50_ms >= 0)
        and (.p95_ms | type == "number")
        and (.p95_ms >= .p50_ms)
        and (.p99_ms | type == "number")
        and (.p99_ms >= .p95_ms)
        and (.max_ms | type == "number")
        and (.max_ms >= .p99_ms)
        and (.p95_budget_ms | type == "number")
        and (.p95_budget_ms > 0)
        and (.p95_ms <= .p95_budget_ms)
        and (.budget_passed == true)
      ))
      and (.total_requests == ([.categories[].requests] | add))
      and (all(.. | strings; test("[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]") | not))
    ' "$source" >/dev/null || fail performance_schema performance-smoke.json
}

prepare_performance() {
    local source="$raw_root_real/performance-smoke.json"
    local json_output="$candidate_dir/performance-smoke.json"
    local markdown_output="$candidate_dir/performance-smoke.md"

    [[ "$test_status" == 'success' ]] || fail performance_test_failed
    validate_performance_json
    jq --sort-keys . "$source" >"$json_output"
    chmod 600 "$json_output"
    scan_text_file performance-smoke.json "$json_output"

    {
        printf '# ISCY Performance-Smoke\n\n'
        jq --raw-output '
          "- Testzeitpunkt: \(.generated_at)",
          "- Testumgebung: \(.environment)",
          "- Testdauer: \(.duration_ms) ms",
          "- Durchsatz: \(.throughput_per_second) Requests/s",
          "- Timeouts: \(.timeout_count)",
          "- DB-/Service-Unavailable-Antworten: \(.database_connection_errors)",
          "",
          "| Kategorie | Requests | Fehler | p50 ms | p95 ms | p99 ms | Budget |",
          "|---|---:|---:|---:|---:|---:|---:|",
          (.categories[] |
            "| \(.name) | \(.requests) | \(.errors) | \(.p50_ms) | \(.p95_ms) | \(.p99_ms) | \(.p95_budget_ms) |")
        ' "$json_output"
    } >"$markdown_output"
    chmod 600 "$markdown_output"
    [[ "$(stat -c '%s' -- "$markdown_output")" -le 1048576 ]] \
        || fail file_too_large performance-smoke.md
    scan_text_file performance-smoke.md "$markdown_output"
}

validate_png() {
    local relative_path="$1"
    local path="$2"
    local signature
    [[ -f "$path" && ! -L "$path" ]] || fail png_type "$relative_path"
    [[ "$(stat -c '%h' -- "$path")" == '1' ]] || fail hardlink "$relative_path"
    [[ "$(stat -c '%s' -- "$path")" -le 5242880 ]] \
        || fail file_too_large "$relative_path"
    signature="$(od -An -tx1 -N8 -- "$path" | tr -d ' \n')"
    [[ "$signature" == '89504e470d0a1a0a' ]] || fail png_signature "$relative_path"
    python3 - "$path" <<'PY' || fail png_structure "$relative_path"
import re
import struct
import sys
import zlib

data = open(sys.argv[1], "rb").read()
if data[:8] != b"\x89PNG\r\n\x1a\n":
    raise SystemExit(1)

allowed_chunks = {
    b"IHDR", b"PLTE", b"IDAT", b"IEND", b"tRNS",
    b"cHRM", b"gAMA", b"sRGB", b"pHYs",
}
position = 8
seen_ihdr = False
seen_idat = False
idat_closed = False
seen_iend = False

while position < len(data):
    if seen_iend or len(data) - position < 12:
        raise SystemExit(1)
    length = struct.unpack(">I", data[position:position + 4])[0]
    chunk_type = data[position + 4:position + 8]
    chunk_end = position + 12 + length
    if (
        chunk_type not in allowed_chunks
        or not re.fullmatch(rb"[A-Za-z]{4}", chunk_type)
        or chunk_end > len(data)
    ):
        raise SystemExit(1)
    chunk_data = data[position + 8:position + 8 + length]
    expected_crc = struct.unpack(">I", data[position + 8 + length:chunk_end])[0]
    if (zlib.crc32(chunk_type + chunk_data) & 0xFFFFFFFF) != expected_crc:
        raise SystemExit(1)

    if chunk_type == b"IHDR":
        if seen_ihdr or position != 8 or length != 13:
            raise SystemExit(1)
        width, height = struct.unpack(">II", chunk_data[:8])
        if width < 1 or height < 1 or width > 20000 or height > 20000:
            raise SystemExit(1)
        seen_ihdr = True
    elif not seen_ihdr:
        raise SystemExit(1)

    if chunk_type == b"IDAT":
        if idat_closed:
            raise SystemExit(1)
        seen_idat = True
    elif seen_idat and chunk_type != b"IEND":
        idat_closed = True

    if chunk_type == b"IEND":
        if length != 0 or not seen_idat:
            raise SystemExit(1)
        seen_iend = True

    position = chunk_end

if not (seen_ihdr and seen_idat and seen_iend and position == len(data)):
    raise SystemExit(1)
PY
    [[ "$(file --brief --mime-type -- "$path")" == 'image/png' ]] \
        || fail png_media_type "$relative_path"
}

validate_visual_summary() {
    local source="$raw_root_real/visual-summary-source.json"
    [[ -f "$source" && ! -L "$source" ]] || fail visual_summary_missing
    [[ "$(stat -c '%s' -- "$source")" -le 1048576 ]] \
        || fail file_too_large visual-summary-source.json

    jq --exit-status --arg commit "$expected_commit" --arg outcome "$test_status" '
      def exact_keys($wanted): ((keys | sort) == ($wanted | sort));
      exact_keys([
        "schema_version", "overall_status", "total_tests", "passed", "failed",
        "skipped", "tests", "commit_sha", "synthetic_test_data",
        "contains_secrets", "contains_personal_data"
      ])
      and (.schema_version == 1)
      and (.overall_status | IN("passed", "failed"))
      and (.commit_sha == $commit)
      and (.synthetic_test_data == true)
      and (.contains_secrets == false)
      and (.contains_personal_data == false)
      and (.total_tests | type == "number" and floor == . and . >= 0)
      and (.passed | type == "number" and floor == . and . >= 0)
      and (.failed | type == "number" and floor == . and . >= 0)
      and (.skipped | type == "number" and floor == . and . >= 0)
      and (.total_tests == (.passed + .failed + .skipped))
      and (.tests | type == "array")
      and ((.tests | length) == .total_tests)
      and (all(.tests[];
        exact_keys([
          "project_name", "title", "test_id", "status", "duration_ms",
          "diff_files"
        ])
        and (.project_name | IN("desktop-1440", "laptop-1024"))
        and (.title | type == "string" and length >= 1 and length <= 120
          and test("^[A-Za-z0-9ÄÖÜäöüß][A-Za-z0-9ÄÖÜäöüß._ -]*$"))
        and (.test_id | type == "string" and
          test("^(desktop-1440|laptop-1024)::[a-z0-9][a-z0-9-]{0,100}$"))
        and (.status | IN("passed", "failed", "skipped"))
        and (.duration_ms | type == "number" and floor == . and . >= 0
          and . <= 300000)
        and (.diff_files | type == "array" and length <= 1)
        and (all(.diff_files[];
          type == "string"
          and test("^diffs/[a-z0-9][a-z0-9._-]{0,180}-diff\\.png$")
        ))
      ))
      and (all(.tests[];
        . as $test
        | ($test.test_id | startswith($test.project_name + "::"))
        and (all($test.diff_files[];
          . == ("diffs/" + $test.project_name + "-"
            + ($test.test_id | split("::")[1]) + "-diff.png")
        ))
      ))
      and (([.tests[].test_id] | unique | length) == .total_tests)
      and (([.tests[].diff_files[]] | unique | length)
        == ([.tests[].diff_files[]] | length))
      and (.passed == ([.tests[] | select(.status == "passed")] | length))
      and (.failed == ([.tests[] | select(.status == "failed")] | length))
      and (.skipped == ([.tests[] | select(.status == "skipped")] | length))
      and (
        if $outcome == "success"
        then .overall_status == "passed" and .failed == 0
        else .overall_status == "failed" and .failed > 0
        end
      )
      and (all(.. | strings; test("[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]") | not))
    ' "$source" >/dev/null || fail visual_summary_schema visual-summary-source.json
}

prepare_visual() {
    local source="$raw_root_real/visual-summary-source.json"
    local summary_output="$candidate_dir/visual-summary.json"
    local relative_path source_png output_png
    local expected_diff_list actual_diff_list
    local png_count total_png_size
    local -a png_files=()

    validate_visual_summary
    expected_diff_list="$(jq -r '[.tests[].diff_files[]] | sort | .[]' "$source")"
    actual_diff_list="$(
        find -P "$raw_root_real" -type f -path "$raw_root_real/diffs/*-diff.png" \
            -printf 'diffs/%f\n' | sort
    )"
    [[ "$expected_diff_list" == "$actual_diff_list" ]] || fail visual_diff_set

    jq --sort-keys '
      .tests |= sort_by(.project_name, .test_id)
    ' "$source" >"$summary_output"
    chmod 600 "$summary_output"
    scan_text_file visual-summary.json "$summary_output"

    mapfile -t png_files < <(
        jq -r '[.tests[].diff_files[]] | sort | .[]' "$summary_output"
    )
    png_count="${#png_files[@]}"
    ((png_count <= 50)) || fail visual_png_count
    total_png_size=0
    for relative_path in "${png_files[@]}"; do
        safe_relative_path "$relative_path" || fail visual_diff_path
        source_png="$raw_root_real/$relative_path"
        validate_png "$relative_path" "$source_png"
        total_png_size=$((total_png_size + $(stat -c '%s' -- "$source_png")))
        ((total_png_size <= 26214400)) || fail visual_total_size
        install -d -m 0700 "$candidate_dir/diffs"
        output_png="$candidate_dir/$relative_path"
        install -m 0600 -- "$source_png" "$output_png"
        validate_png "$relative_path" "$output_png"
    done
}

media_type_for() {
    case "$1" in
        *.json) printf 'application/json' ;;
        *.md) printf 'text/markdown; charset=utf-8' ;;
        *.png) printf 'image/png' ;;
        *) return 1 ;;
    esac
}

create_manifest() {
    local classification media_type path relative_path
    local entries_file="$candidate_dir/.manifest-entries.jsonl"
    local -a payload_files=()
    case "$artifact_type" in
        performance) classification='synthetic_aggregate_metrics' ;;
        visual) classification='synthetic_visual_diff' ;;
    esac

    : >"$entries_file"
    mapfile -d '' payload_files < <(
        find -P "$candidate_dir" -type f ! -name '.manifest-entries.jsonl' \
            ! -name 'artifact-manifest.json' -print0 | sort -z
    )
    for path in "${payload_files[@]}"; do
        relative_path="${path#"$candidate_dir"/}"
        safe_relative_path "$relative_path" || fail manifest_path
        media_type="$(media_type_for "$relative_path")" || fail manifest_media_type
        jq --null-input --compact-output \
            --arg path "$relative_path" \
            --arg sha256 "$(sha256sum -- "$path" | cut -d' ' -f1)" \
            --argjson size "$(stat -c '%s' -- "$path")" \
            --arg media_type "$media_type" \
            --arg classification "$classification" \
            '{
              path: $path,
              sha256: $sha256,
              size: $size,
              media_type: $media_type,
              classification: $classification
            }' >>"$entries_file"
    done

    jq --slurp --sort-keys \
        --arg type "$artifact_type" \
        --arg commit "$expected_commit" \
        --arg status "$test_status" \
        --arg classification "$classification" \
        '{
          schema_version: 1,
          artifact_type: $type,
          commit_sha: $commit,
          test_status: $status,
          classification: $classification,
          files: .
        }' "$entries_file" >"$candidate_dir/artifact-manifest.json"
    chmod 600 "$candidate_dir/artifact-manifest.json"
    rm -f -- "$entries_file"
    [[ "$(stat -c '%s' -- "$candidate_dir/artifact-manifest.json")" -le 262144 ]] \
        || fail manifest_size artifact-manifest.json
    scan_text_file artifact-manifest.json "$candidate_dir/artifact-manifest.json"
}

validate_staging() {
    local staging_root="$1"
    local manifest="$staging_root/artifact-manifest.json"
    local path relative_path expected_hash actual_hash expected_size actual_size
    local expected_media actual_media expected_classification
    local manifest_count actual_count total_size mode_decimal
    local -a staging_entries=()

    [[ -d "$staging_root" && ! -L "$staging_root" ]] || fail staging_type
    [[ -f "$manifest" && ! -L "$manifest" ]] || fail manifest_missing
    mapfile -d '' staging_entries < <(
        find -P "$staging_root" -mindepth 1 -print0 | sort -z
    )
    for path in "${staging_entries[@]}"; do
        relative_path="${path#"$staging_root"/}"
        safe_relative_path "$relative_path" || fail staging_path_invalid
        if [[ -L "$path" ]]; then
            fail staging_symlink "$relative_path"
        elif [[ -d "$path" ]]; then
            [[ "$artifact_type" == 'visual' && "$relative_path" == 'diffs' ]] \
                || fail staging_unexpected_directory "$relative_path"
            [[ "$(stat -c '%a' -- "$path")" == '700' ]] \
                || fail staging_directory_permissions "$relative_path"
        elif [[ -f "$path" ]]; then
            [[ "$(stat -c '%h' -- "$path")" == '1' ]] \
                || fail staging_hardlink "$relative_path"
            mode_decimal=$((8#$(stat -c '%a' -- "$path")))
            (( (mode_decimal & 077) == 0 )) \
                || fail staging_file_permissions "$relative_path"
            case "$artifact_type" in
                performance)
                    case "$relative_path" in
                        artifact-manifest.json | performance-smoke.json \
                            | performance-smoke.md) ;;
                        *) fail performance_staging_allowlist "$relative_path" ;;
                    esac
                    ;;
                visual)
                    if [[ "$relative_path" == 'artifact-manifest.json' \
                        || "$relative_path" == 'visual-summary.json' \
                        || "$relative_path" =~ ^diffs/(desktop-1440|laptop-1024)-[a-z0-9][a-z0-9-]{0,100}-diff\.png$ ]]; then
                        :
                    else
                        fail visual_staging_allowlist "$relative_path"
                    fi
                    ;;
            esac
        else
            fail staging_special_file "$relative_path"
        fi
    done
    case "$artifact_type" in
        performance) expected_classification='synthetic_aggregate_metrics' ;;
        visual) expected_classification='synthetic_visual_diff' ;;
    esac
    jq --exit-status \
        --arg type "$artifact_type" \
        --arg commit "$expected_commit" \
        --arg status "$test_status" \
        --arg classification "$expected_classification" '
      ((keys | sort) == ([
        "artifact_type", "classification", "commit_sha", "files",
        "schema_version", "test_status"
      ] | sort))
      and (.schema_version == 1)
      and (.artifact_type == $type)
      and (.commit_sha == $commit)
      and (.test_status == $status)
      and (.classification == $classification)
      and (.files | type == "array" and length >= 1)
      and (all(.files[];
        ((keys | sort)
          == (["classification", "media_type", "path", "sha256", "size"] | sort))
        and (.path | type == "string")
        and (.sha256 | type == "string" and test("^[0-9a-f]{64}$"))
        and (.size | type == "number" and floor == . and . >= 0)
        and (.media_type
          | IN("application/json", "text/markdown; charset=utf-8", "image/png"))
        and (.classification == $classification)
      ))
      and (([.files[].path] | unique | length) == (.files | length))
    ' "$manifest" >/dev/null || fail manifest_schema artifact-manifest.json

    manifest_count="$(jq '.files | length' "$manifest")"
    actual_count="$(
        find -P "$staging_root" -type f ! -name artifact-manifest.json | wc -l
    )"
    [[ "$manifest_count" == "$actual_count" ]] || fail manifest_file_set

    while IFS=$'\t' read -r relative_path expected_hash expected_size \
        expected_media expected_classification; do
        safe_relative_path "$relative_path" || fail manifest_path
        path="$staging_root/$relative_path"
        [[ -f "$path" && ! -L "$path" ]] || fail manifest_file_missing "$relative_path"
        [[ "$(stat -c '%h' -- "$path")" == '1' ]] || fail hardlink "$relative_path"
        actual_hash="$(sha256sum -- "$path" | cut -d' ' -f1)"
        actual_size="$(stat -c '%s' -- "$path")"
        actual_media="$(media_type_for "$relative_path")" || fail manifest_media_type
        [[ "$actual_hash" == "$expected_hash" ]] || fail manifest_hash "$relative_path"
        [[ "$actual_size" == "$expected_size" ]] || fail manifest_file_size "$relative_path"
        [[ "$actual_media" == "$expected_media" ]] || fail manifest_media_type "$relative_path"
        [[ "$expected_classification" == "$(jq -r '.classification' "$manifest")" ]] \
            || fail manifest_classification "$relative_path"
    done < <(
        jq -r '.files[] |
          [.path, .sha256, (.size | tostring), .media_type, .classification] |
          @tsv' "$manifest"
    )

    case "$artifact_type" in
        performance)
            [[ "$(find -P "$staging_root" -type f -printf '%P\n' | sort)" == \
                $'artifact-manifest.json\nperformance-smoke.json\nperformance-smoke.md' ]] \
                || fail performance_staging_allowlist
            ;;
        visual)
            find -P "$staging_root" -type f -printf '%P\n' \
                | grep -Ev '^(artifact-manifest\.json|visual-summary\.json|diffs/[a-z0-9][a-z0-9._-]*-diff\.png)$' \
                | grep -q . && fail visual_staging_allowlist
            ;;
    esac

    total_size="$(
        find -P "$staging_root" -type f -printf '%s\n' \
            | awk '{total += $1} END {print total + 0}'
    )"
    case "$artifact_type" in
        performance) ((total_size <= 2097152)) || fail performance_total_size ;;
        visual) ((total_size <= 26214400)) || fail visual_total_size ;;
    esac
}

validate_raw_tree
inventory_before="$(mktemp "$workspace_root/.ci-artifact-inventory-before.XXXXXX")"
inventory_after="$(mktemp "$workspace_root/.ci-artifact-inventory-after.XXXXXX")"
write_inventory "$inventory_before"

candidate_dir="$(mktemp -d "$workspace_root/.ci-artifact-candidate.XXXXXX")"
chmod 700 "$candidate_dir"
case "$artifact_type" in
    performance) prepare_performance ;;
    visual) prepare_visual ;;
esac
create_manifest
validate_staging "$candidate_dir"

case "$test_failure_point" in
    wait_after_validation)
        test_ready_marker="$workspace_root/.ci-artifact-test-ready"
        test_continue_marker="$workspace_root/.ci-artifact-test-continue"
        : >"$test_ready_marker"
        for _ in $(seq 1 200); do
            [[ ! -e "$test_continue_marker" ]] || break
            sleep 0.01
        done
        [[ -e "$test_continue_marker" ]] || fail test_sync_timeout
        ;;
    signal_int_during_processing) kill -INT "$$" ;;
    signal_term_during_processing) kill -TERM "$$" ;;
    signal_hup_during_processing) kill -HUP "$$" ;;
esac

write_inventory "$inventory_after"
cmp --silent "$inventory_before" "$inventory_after" || fail source_changed

case "$test_failure_point" in
    between_validation_and_publish) fail injected_before_publish ;;
esac

mv -T -- "$candidate_dir" "$output_root"
candidate_dir=''
output_created=1

case "$test_failure_point" in
    wait_after_publish)
        test_ready_marker="$workspace_root/.ci-artifact-test-ready"
        test_continue_marker="$workspace_root/.ci-artifact-test-continue"
        : >"$test_ready_marker"
        for _ in $(seq 1 200); do
            [[ ! -e "$test_continue_marker" ]] || break
            sleep 0.01
        done
        [[ -e "$test_continue_marker" ]] || fail test_sync_timeout
        ;;
    after_publish) fail injected_after_publish ;;
esac

validate_staging "$output_root"
transaction_complete=1
printf 'CI_ARTIFACT_OK type=%s files=%s\n' \
    "$artifact_type" "$(find -P "$output_root" -type f | wc -l)"
