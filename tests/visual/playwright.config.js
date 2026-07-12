const path = require("path");
const { defineConfig } = require("@playwright/test");

module.exports = defineConfig({
  testDir: path.join(__dirname, "specs"),
  outputDir: process.env.ISCY_VISUAL_ARTIFACT_DIR || path.join(__dirname, "artifacts"),
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
    [
      "json",
      {
        outputFile:
          process.env.ISCY_VISUAL_REPORT ||
          path.join(__dirname, "artifacts", "visual-report.json"),
      },
    ],
  ],
  use: {
    baseURL: process.env.ISCY_VISUAL_BASE_URL || "http://127.0.0.1:19200",
    locale: "de-DE",
    timezoneId: "Europe/Berlin",
    colorScheme: "light",
    reducedMotion: "reduce",
    screenshot: "only-on-failure",
    trace: "retain-on-failure",
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
