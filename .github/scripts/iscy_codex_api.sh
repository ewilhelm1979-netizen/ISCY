#!/usr/bin/env bash
set -euo pipefail
umask 077

readonly EXPECTED_REPOSITORY='ewilhelm1979-netizen/ISCY'

fail_local() {
  printf '::error title=ISCY Codex API::ISCY_CODEX_API_LOCAL_ERROR[%s]: %s\n' \
    "$1" "$2" >&2
  exit 1
}

validate_pr_number() {
  [[ "$1" =~ ^[1-9][0-9]*$ ]] || fail_local "$2" invalid_pr_number
}

validate_sha() {
  [[ "$1" =~ ^[0-9a-f]{40}$ ]] || fail_local "$2" invalid_head_sha
}

[[ $# -eq 4 ]] || fail_local usage invalid_argument_count

operation="$1"
repository="$2"
identifier="$3"
file_path="$4"

[[ "$repository" == "$EXPECTED_REPOSITORY" ]] \
  || fail_local "$operation" invalid_repository
[[ -n "${GH_TOKEN:-}" ]] || fail_local "$operation" missing_token
command -v gh >/dev/null 2>&1 || fail_local "$operation" missing_gh

declare -a gh_args
write_response='true'
case "$operation" in
  pull_request_read)
    validate_pr_number "$identifier" "$operation"
    gh_args=(api "repos/$repository/pulls/$identifier")
    ;;
  comments_read)
    validate_pr_number "$identifier" "$operation"
    gh_args=(api --paginate --slurp \
      "repos/$repository/issues/$identifier/comments?per_page=100")
    ;;
  check_runs_read)
    validate_sha "$identifier" "$operation"
    gh_args=(api -H 'Accept: application/vnd.github+json' \
      "repos/$repository/commits/$identifier/check-runs?filter=latest&per_page=100")
    ;;
  status_comment_write)
    validate_pr_number "$identifier" "$operation"
    [[ -f "$file_path" ]] || fail_local "$operation" missing_request_body
    gh_args=(api --method POST \
      "repos/$repository/issues/$identifier/comments" --input "$file_path")
    write_response='false'
    ;;
  *) fail_local "$operation" unsupported_operation ;;
esac

printf '::notice title=ISCY Codex API::%s\n' "$operation"

tmp_dir="$(mktemp -d)"
trap 'rm -rf -- "$tmp_dir"' EXIT
response_file="$tmp_dir/response"
error_file="$tmp_dir/error"

if ! gh "${gh_args[@]}" >"$response_file" 2>"$error_file"; then
  http_status='unknown'
  while IFS= read -r error_line; do
    if [[ "$error_line" =~ \(HTTP[[:space:]]([0-9]{3})\) ]]; then
      http_status="${BASH_REMATCH[1]}"
    fi
  done <"$error_file"
  printf '::error title=ISCY Codex API::ISCY_CODEX_API_ERROR[%s]: HTTP %s\n' \
    "$operation" "$http_status" >&2
  exit 1
fi

if [[ "$write_response" == 'true' ]]; then
  [[ -s "$response_file" ]] || fail_local "$operation" empty_response
  mv -- "$response_file" "$file_path" 2>/dev/null \
    || fail_local "$operation" response_store_failed
fi
