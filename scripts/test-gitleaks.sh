#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
audit_tmp="$(mktemp -d "${XDG_RUNTIME_DIR:-/tmp}/iscy-gitleaks-test.XXXXXX")"
trap 'rm -rf -- "$audit_tmp"' EXIT INT TERM

config="$repo_root/.gitleaks.toml"

expect_clean() {
  local target="$1"
  gitleaks dir \
    --config "$config" \
    --no-banner \
    --no-color \
    --redact=100 \
    "$target" >/dev/null
}

expect_finding() {
  local target="$1"
  local forbidden_value="$2"
  local report="$audit_tmp/report.json"
  local output="$audit_tmp/output.log"

  rm -f -- "$report" "$output"
  if gitleaks dir \
    --config "$config" \
    --no-banner \
    --no-color \
    --redact=100 \
    --report-format json \
    --report-path "$report" \
    "$target" >"$output" 2>&1; then
    printf 'expected a Gitleaks finding for %s\n' "$(basename "$target")" >&2
    exit 1
  fi
  if grep -Fq -- "$forbidden_value" "$output" \
    || { [[ -f "$report" ]] && grep -Fq -- "$forbidden_value" "$report"; }; then
    printf 'Gitleaks output was not fully redacted\n' >&2
    exit 1
  fi
}

clean_case="$audit_tmp/clean"
mkdir -p "$clean_case"
printf 'pub const DEVICE_NAME: &str = "HS100";\n' >"$clean_case/source.rs"
expect_clean "$clean_case"

aws_case="$audit_tmp/aws"
mkdir -p "$aws_case"
# Public, non-production fixture from Gitleaks' own rule tests. Keep the
# detector prefix split in source so hosting platforms do not treat this file
# as containing a credential.
aws_value="AKIA""IMNOJVGFDXXXE4OA"
printf 'AWS_ACCESS_KEY_ID=%s\n' "$aws_value" >"$aws_case/.env"
expect_finding "$aws_case" "$aws_value"

github_case="$audit_tmp/github"
mkdir -p "$github_case"
github_body="$(printf 'hs100-gitleaks-github-fixture' | sha256sum | cut -c1-36)"
github_value="ghp_""$github_body"
printf 'GITHUB_TOKEN=%s\n' "$github_value" >"$github_case/.env"
expect_finding "$github_case" "$github_value"

private_key_case="$audit_tmp/private-key"
mkdir -p "$private_key_case"
private_key_header="-----BEGIN PRIVATE"" KEY-----"
private_key_footer="-----END PRIVATE"" KEY-----"
printf -v private_key_body '%064d' 0
printf '%s\n%s\n%s\n' \
  "$private_key_header" \
  "$private_key_body" \
  "$private_key_footer" >"$private_key_case/key.pem"
expect_finding "$private_key_case" "$private_key_header"

password_case="$audit_tmp/password"
mkdir -p "$password_case"
db_test_value="Secret""2024!"
printf 'DB_PASS="%s"\n' "$db_test_value" >"$password_case/config.sh"
expect_finding "$password_case" "$db_test_value"

allowlisted_case="$audit_tmp/tests/gitleaks"
mkdir -p "$allowlisted_case"
allowlisted_value="TestOnly-""NotARealSecret"
printf 'DB_PASSWORD="%s"\n' "$allowlisted_value" \
  >"$allowlisted_case/allowed-db-password.env"
expect_clean "$allowlisted_case/allowed-db-password.env"

placeholder_case="$audit_tmp/docs"
mkdir -p "$placeholder_case"
placeholder="YOUR_API_""KEY_HERE"
printf 'API_KEY = "%s"\n' "$placeholder" >"$placeholder_case/SECURITY.md"
expect_clean "$placeholder_case/SECURITY.md"

unexpected_placeholder="$audit_tmp/unexpected-placeholder"
mkdir -p "$unexpected_placeholder"
printf 'API_KEY = "%s"\n' "$placeholder" >"$unexpected_placeholder/example.md"
expect_finding "$unexpected_placeholder" "$placeholder"

worktree_source="$audit_tmp/worktree-source"
worktree_checkout="$audit_tmp/worktree-checkout"
mkdir -p "$worktree_source/scripts"
cp -- "$repo_root/.gitleaks.toml" "$worktree_source/.gitleaks.toml"
cp -- "$repo_root/scripts/run-gitleaks.sh" "$worktree_source/scripts/run-gitleaks.sh"
printf 'synthetic clean worktree fixture\n' >"$worktree_source/fixture.txt"
git init --quiet --initial-branch=fixture "$worktree_source"
git -C "$worktree_source" add .gitleaks.toml scripts/run-gitleaks.sh fixture.txt
git -C "$worktree_source" \
  -c user.name='ISCY Gitleaks Test' \
  -c user.email='gitleaks-test@example.invalid' \
  commit --quiet -m 'test: add clean worktree fixture'
git -C "$worktree_source" worktree add --quiet -b fixture-worktree "$worktree_checkout"
worktree_output="$(bash "$worktree_checkout/scripts/run-gitleaks.sh" dir fixture-worktree)"
[[ "$worktree_output" == *'dir-Scan: sauber'* ]] || {
  printf 'Gitleaks runner rejected a valid Git worktree\n' >&2
  exit 1
}

printf 'Gitleaks policy tests passed with redacted output.\n'
