#!/usr/bin/env bash
set -euo pipefail
umask 077

readonly NO_DIFF_EXIT=3
diff_tmp_dir=''

cleanup() {
  if [[ -n "$diff_tmp_dir" ]]; then
    rm -rf -- "$diff_tmp_dir"
  fi
}

trap cleanup EXIT INT TERM

fail() {
  printf 'ISCY_CODEX_DIFF_ERROR[%s]: %s\n' "$1" "$2" >&2
  exit 1
}

validate_sha() {
  [[ "$1" =~ ^[0-9a-f]{40}$ ]] || fail sha 'Ungueltiger Commit-SHA.'
}

remote_head() {
  local head_ref="$1"
  if [[ "${ISCY_TEST_MODE:-false}" == 'true' ]]; then
    validate_sha "${ISCY_REMOTE_HEAD_OVERRIDE:-}"
    printf '%s\n' "$ISCY_REMOTE_HEAD_OVERRIDE"
    return
  fi
  git ls-remote --exit-code --heads origin "refs/heads/$head_ref" \
    | awk 'NR == 1 {print $1}'
}

is_protected_path() {
  case "$1" in
    .github/workflows/* | \
      .github/scripts/iscy_codex_* | \
      .codex/* | \
      AGENTS.md | */AGENTS.md | \
      SECURITY.md | */SECURITY.md | \
      deny.toml | \
      scripts/check_release_sensitive_data.sh | \
      release/iscy-backend.cdx.json | \
      release/published/* | \
      docs/releases/*)
      return 0
      ;;
    *) return 1 ;;
  esac
}

is_allowed_binary() {
  case "$1" in
    docs/*.pdf | docs/assets/*.png | tests/visual/baselines/*.png)
      return 0
      ;;
    *) return 1 ;;
  esac
}

validate_local_tags() {
  [[ "${ISCY_TEST_MODE:-false}" == 'true' ]] && return 0
  local local_tags remote_tags unexpected
  local_tags="$(mktemp)"
  remote_tags="$(mktemp)"
  git for-each-ref --format='%(refname)' refs/tags | sort -u >"$local_tags"
  git ls-remote --tags origin \
    | awk '{sub(/\^\{\}$/, "", $2); print $2}' \
    | sort -u >"$remote_tags"
  unexpected="$(comm -23 "$local_tags" "$remote_tags")"
  rm -f -- "$local_tags" "$remote_tags"
  [[ -z "$unexpected" ]] || fail release_ref 'Ein nicht veroeffentlichter lokaler Tag wurde erkannt.'
}

validate_diff() {
  local worktree="${1:-}"
  local expected_head="${2:-}"
  local head_ref="${3:-}"
  local maintenance_allowed="${4:-false}"
  [[ -d "$worktree/.git" || -f "$worktree/.git" ]] || fail worktree 'Git-Arbeitsbaum fehlt.'
  validate_sha "$expected_head"
  [[ "$head_ref" != 'main' && "$head_ref" != dependabot/* && -n "$head_ref" ]] \
    || fail branch 'Ungueltiger Head-Branch.'
  [[ "$maintenance_allowed" == 'true' || "$maintenance_allowed" == 'false' ]] \
    || fail usage 'maintenance_allowed muss true oder false sein.'

  cd "$worktree"
  [[ "$(git rev-parse HEAD)" == "$expected_head" ]] \
    || fail local_head 'Der lokale Head entspricht nicht dem erwarteten PR-Head.'
  [[ "$(remote_head "$head_ref")" == "$expected_head" ]] \
    || fail remote_head_race 'Der Remote-Head hat sich geaendert.'
  validate_local_tags

  if git ls-files --error-unmatch '.codex/runtime/**' >/dev/null 2>&1; then
    fail runtime 'Dateien unter .codex/runtime duerfen nicht getrackt sein.'
  fi

  local path
  while IFS= read -r -d '' path; do
    [[ "$path" != .codex/runtime/* ]] \
      || fail runtime 'Dateien unter .codex/runtime duerfen nicht in den Diff.'
    [[ "$path" != *.log ]] || fail log 'Ungetrackte Logdateien sind nicht erlaubt.'
    git add --intent-to-add -- "$path"
  done < <(git ls-files --others --exclude-standard -z)

  if git diff --quiet HEAD --; then
    printf 'ISCY_CODEX_DIFF_EMPTY: Codex hat keine Aenderung erzeugt.\n' >&2
    exit "$NO_DIFF_EXIT"
  fi

  while IFS= read -r -d '' path; do
    [[ "$path" != .codex/runtime/* ]] \
      || fail runtime 'Dateien unter .codex/runtime duerfen nicht in den Diff.'
    if [[ "$maintenance_allowed" != 'true' ]] && is_protected_path "$path"; then
      fail protected "Geschuetzte Datei im normalen Feature-Fix: $path"
    fi
  done < <(git diff --name-only -z HEAD --)

  if git diff --raw HEAD -- \
    | awk '$1 ~ /^:120000/ || $1 ~ /^:160000/ || $2 == "120000" || $2 == "160000" {found=1} END {exit !found}'; then
    fail special_file 'Symlinks und Git-Submodule sind nicht erlaubt.'
  fi
  [[ ! -e .gitmodules ]] || fail submodule '.gitmodules ist nicht erlaubt.'

  local added deleted binary_path
  while IFS=$'\t' read -r added deleted binary_path; do
    [[ "$added" == '-' && "$deleted" == '-' ]] || continue
    is_allowed_binary "$binary_path" \
      || fail binary "Binaerdatei ausserhalb der freigegebenen Pfade: $binary_path"
  done < <(git diff --numstat HEAD --)

  local added_lines local_root
  diff_tmp_dir="$(mktemp -d)"
  added_lines="$diff_tmp_dir/added-lines.txt"
  git diff --no-ext-diff --unified=0 HEAD -- \
    | awk '/^\+\+\+ / {next} /^\+/ {sub(/^\+/, ""); print}' >"$added_lines"
  local_root='/'"home"'/'
  if grep -Eiq \
    -e '-----BEGIN ([A-Z0-9 ]+ )?PRIVATE KEY-----|gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,}|xox[baprs]-[A-Za-z0-9-]{10,}|sk-[A-Za-z0-9]{20,}' \
    "$added_lines"; then
    fail secret 'Ein moegliches Secret wurde im Diff erkannt.'
  fi
  if grep -Fq -- "$local_root" "$added_lines"; then
    fail local_path 'Ein lokaler absoluter Pfad wurde im Diff erkannt.'
  fi

  git diff --check HEAD -- || fail whitespace 'git diff --check ist fehlgeschlagen.'

  local scanner="${ISCY_TRUSTED_SCANNER:-scripts/check_release_sensitive_data.sh}"
  [[ -f "$scanner" ]] || fail scanner 'Sensitive-Data-Scanner fehlt.'
  bash "$scanner"

  local file_count insertion_count deletion_count
  file_count="$(git diff --name-only HEAD -- | wc -l | tr -d ' ')"
  read -r insertion_count deletion_count < <(
    git diff --numstat HEAD -- \
      | awk '$1 != "-" {a += $1} $2 != "-" {d += $2} END {print a + 0, d + 0}'
  )
  jq -cn \
    --arg head "$expected_head" \
    --argjson files "$file_count" \
    --argjson insertions "$insertion_count" \
    --argjson deletions "$deletion_count" \
    '{validated_head:$head, files:$files, insertions:$insertions, deletions:$deletions}'
}

validate_diff "${1:-}" "${2:-}" "${3:-}" "${4:-false}"
