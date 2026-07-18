#!/usr/bin/env bash
set -euo pipefail
umask 077

readonly EXPECTED_REPOSITORY='ewilhelm1979-netizen/ISCY'

fail() {
  printf 'ISCY_CODEX_PUSH_ERROR[%s]: %s\n' "$1" "$2" >&2
  exit 1
}

validate_sha() {
  [[ "$1" =~ ^[0-9a-f]{40}$ ]] || fail sha 'Ungueltiger Commit-SHA.'
}

remote_head() {
  git ls-remote --exit-code --heads origin "refs/heads/$1" \
    | awk 'NR == 1 {print $1}'
}

commit_push() {
  local worktree="${1:-}"
  local patch_file="${2:-}"
  local expected_head="${3:-}"
  local head_ref="${4:-}"
  local pr_number="${5:-}"
  local attempt="${6:-}"
  local repository="${7:-}"
  [[ "$repository" == "$EXPECTED_REPOSITORY" ]] || fail repository 'Falsches Repository.'
  [[ -d "$worktree/.git" || -f "$worktree/.git" ]] || fail worktree 'Git-Arbeitsbaum fehlt.'
  [[ -s "$patch_file" ]] || fail patch 'Patch fehlt oder ist leer.'
  validate_sha "$expected_head"
  [[ "$head_ref" != 'main' && "$head_ref" != dependabot/* && -n "$head_ref" ]] \
    || fail branch 'Ungueltiger Head-Branch.'
  [[ "$pr_number" =~ ^[1-9][0-9]*$ ]] || fail pull_request 'Ungueltige PR-Nummer.'
  [[ "$attempt" == '1' || "$attempt" == '2' ]] || fail attempt 'Ungueltiger Fix-Versuch.'
  [[ -n "${ISCY_PUSH_TOKEN:-}" ]] || fail token 'Push-Token fehlt.'

  cd "$worktree"
  [[ -z "$(git status --porcelain)" ]] || fail dirty 'Arbeitsbaum ist vor Patch-Anwendung nicht sauber.'
  [[ "$(git rev-parse HEAD)" == "$expected_head" ]] \
    || fail local_head 'Lokaler Head stimmt nicht.'
  [[ "$(remote_head "$head_ref")" == "$expected_head" ]] \
    || fail remote_head_race 'Remote-Head hat sich vor Patch-Anwendung geaendert.'

  git apply --check --binary "$patch_file"
  git apply --index --binary "$patch_file"
  [[ -n "$(git diff --cached --name-only)" ]] || fail empty 'Patch erzeugt keinen Commit.'

  if [[ -n "${ISCY_TRUSTED_DIFF_GUARD:-}" ]]; then
    [[ -x "$ISCY_TRUSTED_DIFF_GUARD" ]] || fail diff_guard 'Vertrauenswuerdiger Diff-Guard fehlt.'
    ISCY_TRUSTED_SCANNER="${ISCY_TRUSTED_SCANNER:-}" \
      "$ISCY_TRUSTED_DIFF_GUARD" \
      "$worktree" "$expected_head" "$head_ref" "${ISCY_MAINTENANCE_ALLOWED:-false}" >/dev/null
  fi

  git config user.name 'github-actions[bot]'
  git config user.email '41898282+github-actions[bot]@users.noreply.github.com'
  git commit -m "codex: fix CI for PR #${pr_number} (attempt ${attempt})"

  [[ "$(remote_head "$head_ref")" == "$expected_head" ]] \
    || fail remote_head_race 'Remote-Head hat sich unmittelbar vor dem Push geaendert.'

  local basic
  basic="$(printf 'x-access-token:%s' "$ISCY_PUSH_TOKEN" | base64 | tr -d '\n')"
  GIT_CONFIG_COUNT=1 \
    GIT_CONFIG_KEY_0="http.https://github.com/.extraheader" \
    GIT_CONFIG_VALUE_0="AUTHORIZATION: basic $basic" \
    git push origin "HEAD:refs/heads/$head_ref"

  local new_head
  new_head="$(git rev-parse HEAD)"
  validate_sha "$new_head"
  if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
    printf 'new_head=%s\n' "$new_head" >>"$GITHUB_OUTPUT"
  fi
  printf '%s\n' "$new_head"
}

commit_push "$@"
