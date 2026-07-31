const path = require("path");
const { defineConfig } = require("@playwright/test");

const outputRoot = process.env.ISCY_PLAYWRIGHT_OUTPUT_ROOT;
if (!outputRoot) {
  throw new Error("VISUAL_CONFIG_ERROR[playwright_output_root_missing]");
}

module.exports = defineConfig({
  testDir: path.join(__dirname, "specs"),
  outputDir: outputRoot,
  snapshotPathTemplate: path.join(
    __dirname,
    "baselines",
    "{projectName}",
    "{arg}{ext}",
  ),
  timeout: 30_000,
  expect: {
    timeout: 5_000,
    toHaveScreenshot: {
      animations: "disabled",
      maxDiffPixelRatio: 0.003,
      threshold: 0.15,
    },
  },
  fullyParallel: false,
  workers: 1,
  retries: 0,
  reporter: [
    ["line"],
    [path.join(__dirname, "synthetic-summary-reporter.js")],
  ],
  use: {
    baseURL: process.env.ISCY_VISUAL_BASE_URL,
    locale: "de-DE",
    timezoneId: "Europe/Berlin",
    colorScheme: "light",
    reducedMotion: "reduce",
    screenshot: "off",
    trace: "off",
    video: "off",
    acceptDownloads: false,
    serviceWorkers: "block",
  },
  projects: [
    {
      name: "desktop-1440",
      use: { viewport: { width: 1440, height: 1200 } },
    },
    {
      name: "laptop-1024",
      use: { viewport: { width: 1024, height: 900 } },
    },
  ],
});
