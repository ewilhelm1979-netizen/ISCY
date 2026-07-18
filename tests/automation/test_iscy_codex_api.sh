#!/usr/bin/env bash
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
helper="$repo_root/.github/scripts/iscy_codex_api.sh"
tmp_dir="$(mktemp -d)"
trap 'rm -rf -- "$tmp_dir"' EXIT
mkdir -p "$tmp_dir/bin"

cat >"$tmp_dir/bin/gh" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' 'UNSAFE_RESPONSE_PAYLOAD'
printf '%s\n' 'gh: Resource not accessible by integration (HTTP 403)' >&2
exit 1
EOF
chmod +x "$tmp_dir/bin/gh"
printf '%s\n' '{}' >"$tmp_dir/comment.json"

operations=(
  pull_request_read
  comments_read
  check_runs_read
  status_comment_write
)

for operation in "${operations[@]}"; do
  output_file="$tmp_dir/$operation.out"
  case "$operation" in
    pull_request_read|comments_read)
      identifier='67'
      file_path="$output_file"
      ;;
    check_runs_read)
      identifier='0123456789abcdef0123456789abcdef01234567'
      file_path="$output_file"
      ;;
    status_comment_write)
      identifier='67'
      file_path="$tmp_dir/comment.json"
      ;;
  esac

  if PATH="$tmp_dir/bin:$PATH" GH_TOKEN='fixture' \
    bash "$helper" "$operation" 'ewilhelm1979-netizen/ISCY' \
      "$identifier" "$file_path" >"$tmp_dir/log" 2>&1; then
    printf 'expected HTTP 403 failure for %s\n' "$operation" >&2
    exit 1
  fi

  grep -Fx "::notice title=ISCY Codex API::$operation" "$tmp_dir/log" >/dev/null
  grep -Fx \
    "::error title=ISCY Codex API::ISCY_CODEX_API_ERROR[$operation]: HTTP 403" \
    "$tmp_dir/log" >/dev/null
  if grep -F 'UNSAFE_RESPONSE_PAYLOAD' "$tmp_dir/log" >/dev/null; then
    printf 'response payload leaked for %s\n' "$operation" >&2
    exit 1
  fi
  if [[ "$operation" != 'status_comment_write' && -s "$output_file" ]]; then
    printf 'failed response persisted for %s\n' "$operation" >&2
    exit 1
  fi
done

echo 'test_iscy_codex_api: OK'
