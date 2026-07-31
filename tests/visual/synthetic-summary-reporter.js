"use strict";

const fs = require("fs");
const path = require("path");

function requireEnvironment(name) {
  const value = process.env[name];
  if (!value) {
    throw new Error(`VISUAL_REPORTER_ERROR[missing_${name.toLowerCase()}]`);
  }
  return value;
}

function slugify(value) {
  return value
    .normalize("NFKD")
    .replace(/[\u0300-\u036f]/g, "")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 100);
}

function isWithin(root, candidate) {
  const relative = path.relative(root, candidate);
  return relative !== "" && !relative.startsWith(`..${path.sep}`) && relative !== "..";
}

class SyntheticSummaryReporter {
  constructor() {
    this.tests = [];
    this.ids = new Set();
  }

  onBegin() {
    this.rawRoot = fs.realpathSync(requireEnvironment("ISCY_VISUAL_RAW_ROOT"));
    const configuredOutputRoot = requireEnvironment("ISCY_PLAYWRIGHT_OUTPUT_ROOT");
    if (!path.isAbsolute(configuredOutputRoot)) {
      throw new Error("VISUAL_REPORTER_ERROR[output_root_not_absolute]");
    }
    // Playwright leert outputDir unmittelbar vor onBegin und legt es danach
    // neu an. Der kanonische Parent wurde bereits vom Shell-Runner geprüft.
    this.playwrightOutputRoot = path.resolve(configuredOutputRoot);
    this.commitSha = requireEnvironment("ISCY_EXPECTED_COMMIT_SHA");
    if (!/^[0-9a-f]{40}$/.test(this.commitSha)) {
      throw new Error("VISUAL_REPORTER_ERROR[commit_sha_format]");
    }
  }

  onTestEnd(test, result) {
    const projectName = test.parent.project().name;
    const title = test.title;
    const slug = slugify(title);
    const testId = `${projectName}::${slug}`;
    if (
      !["desktop-1440", "laptop-1024"].includes(projectName) ||
      !slug ||
      this.ids.has(testId)
    ) {
      throw new Error("VISUAL_REPORTER_ERROR[test_identity]");
    }
    this.ids.add(testId);

    let status = "failed";
    if (result.status === "passed") {
      status = "passed";
    } else if (result.status === "skipped") {
      status = "skipped";
    }

    const diffFiles = [];
    for (const attachment of result.attachments || []) {
      if (!attachment.path || !path.basename(attachment.path).endsWith("-diff.png")) {
        continue;
      }
      const source = fs.realpathSync(attachment.path);
      if (!isWithin(this.playwrightOutputRoot, source)) {
        throw new Error("VISUAL_REPORTER_ERROR[diff_source_boundary]");
      }
      const diffDirectory = path.join(this.rawRoot, "diffs");
      fs.mkdirSync(diffDirectory, { mode: 0o700, recursive: true });
      fs.chmodSync(diffDirectory, 0o700);
      const relativeDestination = `diffs/${projectName}-${slug}-diff.png`;
      const destination = path.join(this.rawRoot, relativeDestination);
      fs.copyFileSync(source, destination, fs.constants.COPYFILE_EXCL);
      fs.chmodSync(destination, 0o600);
      diffFiles.push(relativeDestination);
    }

    this.tests.push({
      project_name: projectName,
      title,
      test_id: testId,
      status,
      duration_ms: Math.max(0, Math.trunc(result.duration || 0)),
      diff_files: diffFiles.sort(),
    });
  }

  async onEnd() {
    const tests = this.tests.sort((left, right) =>
      left.test_id.localeCompare(right.test_id, "en"),
    );
    const passed = tests.filter((entry) => entry.status === "passed").length;
    const failed = tests.filter((entry) => entry.status === "failed").length;
    const skipped = tests.filter((entry) => entry.status === "skipped").length;
    const summary = {
      schema_version: 1,
      overall_status: failed === 0 ? "passed" : "failed",
      total_tests: tests.length,
      passed,
      failed,
      skipped,
      tests,
      commit_sha: this.commitSha,
      synthetic_test_data: true,
      contains_secrets: false,
      contains_personal_data: false,
    };
    const temporaryPath = path.join(
      this.rawRoot,
      `.visual-summary-source.${process.pid}.tmp`,
    );
    const finalPath = path.join(this.rawRoot, "visual-summary-source.json");
    fs.writeFileSync(temporaryPath, `${JSON.stringify(summary, null, 2)}\n`, {
      encoding: "utf8",
      mode: 0o600,
      flag: "wx",
    });
    fs.renameSync(temporaryPath, finalPath);
    fs.chmodSync(finalPath, 0o600);
  }
}

module.exports = SyntheticSummaryReporter;
