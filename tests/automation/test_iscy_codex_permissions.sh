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

pull_request_read_only_jobs = {
  ".github/workflows/iscy-codex-command.yml" =>
    %w[guard],
  ".github/workflows/iscy-codex-ci-loop.yml" =>
    %w[locate-pull-request],
  ".github/workflows/iscy-codex-reusable.yml" =>
    %w[route review-or-verify fix-agent push-fix]
}

fully_read_only_jobs = {
  ".github/workflows/iscy-codex-command.yml" =>
    %w[guard],
  ".github/workflows/iscy-codex-ci-loop.yml" =>
    %w[locate-pull-request],
  ".github/workflows/iscy-codex-reusable.yml" =>
    %w[route review-or-verify fix-agent]
}

reusable_callers = {
  ".github/workflows/iscy-codex-command.yml" =>
    %w[review fix-ci verify],
  ".github/workflows/iscy-codex-ci-loop.yml" =>
    %w[orchestrate]
}

workflows = write_jobs.keys.to_h do |path|
  [path, YAML.safe_load(File.read(path), aliases: true)]
end

workflows.each do |path, workflow|
  abort("global permissions present: #{path}") if workflow.key?("permissions")
  workflow.fetch("jobs").each do |name, job|
    permissions = job["permissions"]
    abort("missing explicit job permissions: #{path}:#{name}") \
      unless permissions.is_a?(Hash) && !permissions.empty?
  end
end

write_jobs.each do |path, expected_jobs|
  workflow = workflows.fetch(path)
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

pull_request_read_only_jobs.each do |path, expected_jobs|
  jobs = workflows.fetch(path).fetch("jobs")
  expected_jobs.each do |name|
    permissions = jobs.fetch(name).fetch("permissions")
    abort("pull-request read-only job changed: #{path}:#{name}") \
      unless permissions["pull-requests"] == "read"
  end
end

fully_read_only_jobs.each do |path, expected_jobs|
  jobs = workflows.fetch(path).fetch("jobs")
  expected_jobs.each do |name|
    permissions = jobs.fetch(name).fetch("permissions")
    abort("read-only job gained write permission: #{path}:#{name}") \
      if permissions.value?("write")
  end
end

reusable_jobs = workflows.fetch(
  ".github/workflows/iscy-codex-reusable.yml"
).fetch("jobs")
permission_rank = { "none" => 0, "read" => 1, "write" => 2 }

reusable_callers.each do |path, caller_names|
  jobs = workflows.fetch(path).fetch("jobs")
  caller_names.each do |name|
    permissions = jobs.fetch(name).fetch("permissions")
    abort("reusable caller gained issue permission: #{path}:#{name}") \
      if permissions.key?("issues")
    reusable_jobs.each do |nested_name, nested_job|
      nested_job.fetch("permissions").each do |scope, nested_access|
        caller_access = permissions.fetch(scope, "none")
        abort(
          "reusable permission ceiling exceeded: #{path}:#{name} -> " \
          "#{nested_name}:#{scope} (#{caller_access} < #{nested_access})"
        ) if permission_rank.fetch(caller_access) < permission_rank.fetch(nested_access)
      end
    end
  end
end

reusable_jobs.each do |name, job|
  abort("nested issue permission exceeds caller ceiling: #{name}") \
    if job.fetch("permissions", {}).key?("issues")
end
RUBY

echo 'test_iscy_codex_permissions: OK'
