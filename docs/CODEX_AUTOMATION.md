# ISCY Codex pull-request automation

ISCY provides a narrowly bounded GitHub-to-Codex handoff for Draft pull
requests. It assists maintainers with review, verification, and at most two
small CI corrections. It does not approve, mark ready, merge, release, tag, or
publish anything. A human remains responsible for review and the final merge.

## Trust model

The orchestrator accepts only pull requests authored by
`ewilhelm1979-netizen`, targeting `main`, from a non-Dependabot branch in the
same repository. The pull request must remain open and Draft and carry
`codex-approved`. Automated operation and `/iscy fix-ci` additionally require
`codex-managed`.

Only comments from the repository owner with association `OWNER` or `MEMBER`
are accepted. After trimming surrounding whitespace, the complete comment must
be exactly one of:

```text
/iscy status
/iscy review
/iscy fix-ci
/iscy verify
```

No comment content is interpolated into a command, path, or Codex prompt. Pull
request content and redacted CI logs remain untrusted diagnostics.

## One-time setup after merge

1. Add the Actions repository secret `OPENAI_API_KEY`.
2. Create the labels `codex-approved`, `codex-managed`,
   `codex-review-ready`, and `codex-automation-maintenance`.
3. Keep existing branch protection and required reviews enabled.
4. Confirm that all current CI and CodeQL checks remain required.
5. Run the first managed correction on a disposable Draft pull request and
   confirm that GitHub schedules CI and CodeQL for the bot-created commit.

The final step is important because GitHub normally suppresses recursive
workflow creation for events produced with a repository `GITHUB_TOKEN`. ISCY
does not introduce a PAT, GitHub App credential, parallel CodeQL workflow, or
security-check bypass. If the repository does not schedule checks for the
bot-created commit, remove `codex-managed` and continue manually until a
separately reviewed authentication design is approved.

## Normal flow

1. A maintainer opens a same-repository Draft pull request.
2. A human reviews its scope and adds `codex-approved` and, when desired,
   `codex-managed`.
3. CI and CodeQL run normally.
4. When all required checks are terminal and any have failed, the orchestrator
   may reserve one of two attempts and prepare a minimal correction.
5. Codex runs without GitHub or push credentials. A trusted guard validates the
   resulting diff and passes only a bounded patch artifact to a separate push
   job.
6. When every required CI and CodeQL check for the exact head is green, Codex
   posts or updates a read-only verification summary.
7. A human reviews, marks ready, and performs the Squash merge.

`READY_FOR_HUMAN_REVIEW` is a comment status, not an approval.

## Security boundaries

- Global workflow permissions are empty; each job receives only its required
  read or write permissions.
- Review and verify use `permission-profile: :read-only`; fixes use
  `permission-profile: :workspace`.
- Every Codex invocation uses `safety-strategy: drop-sudo`, the explicit owner
  allow-list, and `allow-bots: false`.
- The OpenAI key is passed only to the official action input. It is never
  written to context, output, logs, comments, or prompts.
- Checkout credentials are never persisted. The GitHub token is exposed as a
  push credential only in the separate commit/push step.
- Remote head equality is checked before Codex, before patch application,
  before commit, and immediately before the non-force push.
- `.codex/runtime/` is ignored and never uploaded except as explicitly bounded,
  redacted diagnostics inside the running job.
- Normal feature fixes cannot modify workflows, orchestrator scripts, Codex
  policy, repository agent policy, `SECURITY.md`, `deny.toml`, the sensitive
  scanner, SBOM snapshot, or published release snapshots. Automation
  maintenance additionally requires `codex-automation-maintenance`.
- Symlinks, submodules, local tags, secrets, local absolute paths, untracked
  logs, runtime files, and unexpected binaries fail closed.

## Attempt limit

Only exact comments authored by `github-actions[bot]` count:

```text
<!-- iscy-codex-fix-attempt:1 -->
<!-- iscy-codex-fix-attempt:2 -->
```

After both markers exist, no further fix is allowed and the orchestrator posts
`CODEX_STOPPED: maximum_fix_attempts_reached`. Forged user markers, duplicate
markers, and an attempt number outside the range do not increase the count.

## Pinned upstream actions

The automation was reviewed against the official upstream repositories on
2026-07-18 and pins complete commits:

- `openai/codex-action` v1:
  `52fe01ec70a42f454c9d2ebd47598f9fd6893d56`
- `actions/checkout` v7.0.0:
  `9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0`
- `actions/github-script` v9.0.0:
  `3a2844b7e9c422d3c10d287c895573f7108da1b3`
- `actions/upload-artifact` v7.0.0:
  `043fb46d1a93c77aae656e7c1c64a875d1fc6a0a`
- `actions/download-artifact` v8.0.0:
  `3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c`

The Codex CLI is pinned to `0.144.5`. Moving tags such as `@v1`, `@main`, or
`@master` are rejected by the focused automation check.

## Testing

No OpenAI request is made in normal pull-request CI. The local gate runs Bash
syntax checks, ShellCheck, actionlint, a YAML parser, the result-schema check,
guard and injection tests, attempt-limit tests, diff tests, the unchanged
sensitive-data scanner, and `git diff --check`:

```bash
make codex-automation-test
```

The repository's ordinary Rust, supply-chain, Nix, Compose, Docker, CodeQL, and
release-candidate checks remain independent and unchanged.

## Troubleshooting

- **Secret missing:** add `OPENAI_API_KEY`; the Codex job otherwise stops before
  checkout and makes no mutation.
- **Maximum reached:** remove `codex-managed` and investigate manually. Do not
  delete attempt markers to continue automatically.
- **Fork or Dependabot blocked:** expected behavior; use the normal human review
  process.
- **Head changed:** rerun the command only after reviewing the new head.
- **Protected file:** use a dedicated automation pull request and add
  `codex-automation-maintenance` only after human scope review.
- **CodeQL pending:** wait for its next completed workflow event; there is no
  polling loop.
- **API costs:** review and verify each invoke Codex once; every fix attempt
  invokes it once. Status is local GitHub metadata only.
- **Workflow disabled:** re-enable it manually in Actions only after confirming
  labels, secret, branch protection, and policies.

## Emergency stop

Remove `codex-managed` from active pull requests, remove the repository secret,
or disable both `ISCY Codex command` and `ISCY Codex CI loop` in GitHub Actions.
None of these steps changes product code or branch protection.
