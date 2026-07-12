#!/usr/bin/env bash
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

failures=0

report_tracked_matches() {
    local category="$1"
    local pattern="$2"
    local matches
    matches="$(git grep -n -I -E -e "$pattern" -- . ':!scripts/check_release_sensitive_data.sh' || true)"
    if [[ -z "$matches" ]]; then
        return 0
    fi

    while IFS=: read -r file line content; do
        if [[ "$category" == "cloud_access_key" \
            && ( "$file" == "rust/iscy-backend/src/evidence_s3_runtime.rs" \
                || "$file" == "rust/iscy-backend/src/evidence_object_storage.rs" ) \
            && "$content" == *"AKIAIOSFODNN7EXAMPLE"* ]]; then
            continue
        fi
        printf 'SENSITIVE_SCAN finding category=%s location=%s:%s value=redacted\n' \
            "$category" "$file" "$line" >&2
        failures=1
    done <<<"$matches"
}

report_tracked_matches \
    private_key \
    '-----BEGIN ([A-Z0-9 ]+ )?PRIVATE KEY-----'
report_tracked_matches \
    hosted_token \
    'gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,}|xox[baprs]-[A-Za-z0-9-]{10,}|sk-[A-Za-z0-9]{20,}'
report_tracked_matches \
    cloud_access_key \
    '(AKIA|ASIA)[0-9A-Z]{16}'
local_home='/home/'
local_file_scheme='file://'
regex_backslash=$'\\\\'
local_path_pattern="${local_home}[A-Za-z0-9._-]+/|C:${regex_backslash}Users${regex_backslash}|${local_file_scheme}${local_home}"
report_tracked_matches local_absolute_path "$local_path_pattern"

while IFS= read -r file; do
    printf 'SENSITIVE_SCAN finding category=tracked_sensitive_file location=%s value=redacted\n' \
        "$file" >&2
    failures=1
done < <(git ls-files | grep -E '\.(key|pem|p12|pfx|jks|dump|sqlite|sqlite3|db)$' || true)

binary_secret_pattern='-----BEGIN ([A-Z0-9 ]+ )?PRIVATE KEY-----|gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,}|xox[baprs]-[A-Za-z0-9-]{10,}'
while IFS= read -r file; do
    if grep -aEq -e "$binary_secret_pattern" "$file"; then
        printf 'SENSITIVE_SCAN finding category=binary_embedded_secret location=%s value=redacted\n' \
            "$file" >&2
        failures=1
    fi
done < <(git ls-files 'docs/*.pdf' 'docs/assets/*.png' 'tests/visual/baselines/**/*.png')

credential_url_matches="$(
    git grep -n -I -E \
        '(postgres(ql)?|mysql|mongodb(\+srv)?|redis)://[^[:space:]"<>]+:[^[:space:]"<>]+@' \
        -- . || true
)"
if [[ -n "$credential_url_matches" ]]; then
    while IFS=: read -r file line content; do
        if [[ "$content" == *'REPLACE_WITH_STRONG_PASSWORD'* \
            || "$content" == *'change-me'* \
            || "$content" == *'postgresql://isms:isms@'* \
            || "$content" == *'iscy_test_password@'* ]]; then
            printf 'SENSITIVE_SCAN reviewed category=credential_url_example location=%s:%s value=redacted\n' \
                "$file" "$line"
            continue
        fi
        printf 'SENSITIVE_SCAN finding category=credential_url location=%s:%s value=redacted\n' \
            "$file" "$line" >&2
        failures=1
    done <<<"$credential_url_matches"
fi

if [[ -e .env ]]; then
    env_mode="$(stat -c '%a' .env 2>/dev/null || printf 'unknown')"
    printf 'SENSITIVE_SCAN local_ignored_file=.env mode=%s content=not_read\n' "$env_mode"
    if [[ "$env_mode" =~ ^[0-7]{3,4}$ ]]; then
        env_permissions=$((8#$env_mode))
        if (( (env_permissions & 077) != 0 )); then
            echo 'SENSITIVE_SCAN finding category=local_env_permissions location=.env value=redacted' >&2
            failures=1
        fi
    fi
fi
if [[ -e db.sqlite3 ]]; then
    echo 'SENSITIVE_SCAN local_ignored_file=db.sqlite3 content=not_read'
fi

if [[ "$failures" -ne 0 ]]; then
    echo 'SENSITIVE_SCAN FAILED: potenziell sensitive Inhalte muessen geprueft werden.' >&2
    exit 1
fi

echo 'SENSITIVE_SCAN OK: keine hochkonfidenten sensitiven Werte in getrackten Dateien.'
