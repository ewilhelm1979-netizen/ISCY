#!/usr/bin/env bash
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

ruby <<'RUBY'
require "yaml"

write_jobs = {
  ".github/workflows/iscy-codex-command.yml" =>
    %w[status review fix-ci verify],
  ".github/workflows/iscy-codex-ci-loop.yml" =>
    %w[orchestrate],
  ".github/workflows/iscy-codex-reusable.yml" =>
    %w[publish-review-or-verify reserve-fix-attempt publish-fix-result]
}

read_only_jobs = {
  ".github/workflows/iscy-codex-reusable.yml" =>
    %w[route review-or-verify fix-agent push-fix]
}

write_jobs.each do |path, expected_jobs|
  workflow = YAML.safe_load(File.read(path), aliases: true)
  abort("global permissions changed: #{path}") unless workflow["permissions"] == {}
  jobs = workflow.fetch("jobs")
  actual_jobs = jobs.filter_map do |name, job|
    name if job.fetch("permissions", {})["pull-requests"] == "write"
  end
  abort("unexpected pull-request writers: #{path}") unless actual_jobs.sort == expected_jobs.sort

  expected_jobs.each do |name|
    permissions = jobs.fetch(name).fetch("permissions")
    abort("missing pull-request write: #{path}:#{name}") \
      unless permissions["pull-requests"] == "write"
    abort("issue permission retained: #{path}:#{name}") if permissions.key?("issues")
  end
end

read_only_jobs.each do |path, expected_jobs|
  jobs = YAML.safe_load(File.read(path), aliases: true).fetch("jobs")
  expected_jobs.each do |name|
    permissions = jobs.fetch(name).fetch("permissions")
    abort("read-only job changed: #{path}:#{name}") \
      unless permissions["pull-requests"] == "read"
  end
end
RUBY

echo 'test_iscy_codex_permissions: OK'
