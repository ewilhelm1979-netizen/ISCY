#!/usr/bin/env bash
set -euo pipefail

mode="${1:-dir}"
repository_label="${2:-hs100}"
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
audit_tmp="$(mktemp -d "${XDG_RUNTIME_DIR:-/tmp}/${repository_label}-gitleaks.XXXXXX")"
trap 'rm -rf -- "$audit_tmp"' EXIT INT TERM

config="$repo_root/.gitleaks.toml"
report="$audit_tmp/report.json"

if [[ -f "$repo_root/.git/HEAD" ]]; then
  git_command=(git -C "$repo_root")
elif [[ -f "$repo_root/.hs100-git/HEAD" ]]; then
  export GIT_DIR="$repo_root/.hs100-git"
  export GIT_WORK_TREE="$repo_root"
  git_command=(git --git-dir="$GIT_DIR" --work-tree="$GIT_WORK_TREE" -C "$repo_root")
else
  printf '%s\n' "$repository_label: git_metadata_unavailable" >&2
  exit 2
fi

scan_result=0
case "$mode" in
  dir)
    snapshot="$audit_tmp/snapshot"
    mkdir -p "$snapshot"
    while IFS= read -r -d '' relative_path; do
      case "$relative_path" in
        .git/*|.hs100-git/*|target/*|*/target/*|node_modules/*|*/node_modules/*|vendor/*|*/vendor/*|.direnv/*|*/.direnv/*|.cache/*|*/.cache/*|build/*|*/build/*|dist/*|*/dist/*|result|result/*)
          continue
          ;;
      esac
      if [[ "$relative_path" = /* || "$relative_path" = ../* || "$relative_path" = */../* ]]; then
        printf '%s\n' "$repository_label: invalid_repository_path" >&2
        exit 2
      fi
      source_path="$repo_root/$relative_path"
      if [[ -L "$source_path" ]]; then
        continue
      fi
      if [[ ! -f "$source_path" || ! -r "$source_path" ]]; then
        printf '%s: %s: unreadable_in_scope_file\n' \
          "$repository_label" "$relative_path" >&2
        exit 2
      fi
      mkdir -p "$snapshot/$(dirname "$relative_path")"
      cp --reflink=auto -- "$source_path" "$snapshot/$relative_path"
    done < <("${git_command[@]}" ls-files -co --exclude-standard -z)

    set +e
    (
      cd "$snapshot"
      gitleaks dir \
        --config "$config" \
        --no-banner \
        --no-color \
        --redact=100 \
        --max-target-megabytes=5 \
        --report-format json \
        --report-path "$report" \
        . >/dev/null 2>&1
    )
    scan_result=$?
    set -e
    ;;
  history)
    set +e
    (
      cd "$repo_root"
      gitleaks git \
        --config "$config" \
        --no-banner \
        --no-color \
        --redact=100 \
        --report-format json \
        --report-path "$report" \
        . >/dev/null 2>&1
    )
    scan_result=$?
    set -e
    ;;
  *)
    printf 'usage: %s {dir|history} [repository-label]\n' "$0" >&2
    exit 2
    ;;
esac

if [[ -s "$report" ]] && jq -e 'length > 0' "$report" >/dev/null; then
  jq -r --arg repository "$repository_label" '
    .[] |
    "Repository: \($repository)\n" +
    "Dateipfad: \(.File | ltrimstr("./"))\n" +
    "Commit-ID: \((.Commit // "") | if . == "" then "-" else . end)\n" +
    "Zeilennummer: \(.StartLine // "-")\n" +
    "Regel-ID/Secret-Typ: \(.RuleID)\n" +
    "Status: echter Treffer"
  ' "$report"
elif (( scan_result == 0 )); then
  printf 'Repository: %s\n%s-Scan: sauber\n' "$repository_label" "$mode"
else
  printf '%s: gitleaks_scan_failed_closed\n' "$repository_label" >&2
fi

exit "$scan_result"
