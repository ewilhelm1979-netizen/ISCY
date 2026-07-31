const { expect, test } = require("@playwright/test");

let blockedExternalRequests = 0;

test.beforeEach(async ({ context }) => {
  blockedExternalRequests = 0;
  await context.route("**/*", async (route) => {
    let requestOrigin = "";
    try {
      requestOrigin = new URL(route.request().url()).origin;
    } catch {
      blockedExternalRequests += 1;
      await route.abort("blockedbyclient");
      return;
    }
    if (requestOrigin === "http://127.0.0.1:19200") {
      await route.continue();
      return;
    }
    blockedExternalRequests += 1;
    await route.abort("blockedbyclient");
  });
});

test.afterEach(() => {
  expect(
    blockedExternalRequests,
    "VISUAL_NETWORK_ERROR[external_request_blocked]",
  ).toBe(0);
});

const pages = [
  ["login", "/login/", false],
  ["dashboard-betriebsuebersicht", "/dashboard/", true],
  ["organisationsprofil", "/organizations/", true],
  ["management-reviews", "/management-reviews/", true],
  ["regulatory-review-pakete", "/regulatory-review-packs/", true],
  ["evidence-qualitaet", "/evidence/quality/", true],
  ["evidence-integritaet", "/evidence/integrity/", true],
  ["object-storage-runtime", "/evidence/integrity/", true],
  ["supplier-review", "/suppliers/", true],
  ["supplier-product-security", "/suppliers/product-security/", true],
  ["product-security-psirt", "/product-security/", true],
  ["continuous-vulnerability-intelligence", "/cves/", true],
  ["software-approval-exceptions", "/software-policies/", true],
  ["ai-governance", "/ai-governance/", true],
  ["zero-trust-agent-fleet", "/zero-trust/", true],
  ["threat-intelligence-observations", "/security-observations/", true],
  ["agent-rollout-rings", "/zero-trust/rollouts/", true],
  ["agent-artefakte-provenance", "/zero-trust/", true],
  ["agent-pki-csr-mtls", "/zero-trust/", true],
  ["cross-domain-notifications", "/zero-trust/", true],
  ["roadmap-massnahmen", "/roadmap/", true],
];

async function authenticate(page) {
  await page.goto("/login/", { waitUntil: "domcontentloaded" });
  await page.locator('input[name="tenant_id"]').fill("1");
  await page.locator('input[name="username"]').fill("admin");
  await page.locator('input[name="password"]').fill("Admin123!");
  await Promise.all([
    page.waitForURL("**/dashboard/"),
    page.locator('button[type="submit"]').click(),
  ]);
}

async function stabilize(page) {
  await page.addStyleTag({
    content: `
      *, *::before, *::after {
        animation: none !important;
        transition: none !important;
        caret-color: transparent !important;
        font-family: "DejaVu Sans", sans-serif !important;
      }
      html { scroll-behavior: auto !important; }
    `,
  });
  await page.evaluate(() => {
    const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
    while (walker.nextNode()) {
      const node = walker.currentNode;
      node.textContent = node.textContent
        .replace(/20\d{2}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})/g, "ZEITPUNKT")
        .replace(/20\d{2}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?(?: UTC)?/g, "ZEITPUNKT");
    }
  });
  await page.waitForTimeout(100);
}

async function assertSafeUsablePage(page) {
  await expect(page.locator("html")).toHaveAttribute("lang", "de");
  await expect(page.locator("main")).not.toBeEmpty();
  await expect(page.locator("body")).not.toContainText("Internal Server Error");
  await expect(page.locator("body")).not.toContainText("DATABASE_URL");
  await expect(page.locator("body")).not.toContainText("iscy_test_password");
  await expect(page.locator("body")).not.toContainText("Admin123!");
  const text = await page.locator("body").innerText();
  expect(text).not.toMatch(/ha-test\/tenants\/\d+\/evidence\//);
  expect(await page.locator("a, button, input").first().isVisible()).toBe(true);
  const overflow = await page.evaluate(
    () => document.documentElement.scrollWidth - document.documentElement.clientWidth,
  );
  expect(overflow).toBeLessThanOrEqual(1);
  const clippedHeadings = await page.locator("th").evaluateAll((headings) =>
    headings.filter((heading) => heading.scrollWidth > heading.clientWidth + 1).length,
  );
  expect(clippedHeadings).toBe(0);
}

async function assertUnconfiguredEvidenceStorage(page) {
  const storagePanel = page.locator("section.panel").filter({
    has: page.getByRole("heading", {
      name: "Storage-Backend-Status",
      exact: true,
    }),
  });
  const localStorageRow = storagePanel
    .locator("table")
    .first()
    .locator("tbody tr")
    .filter({ hasText: "local_filesystem" });
  await expect(localStorageRow.locator("td")).toHaveText([
    "local_filesystem",
    "aktiv",
    "nicht konfiguriert",
    "storage_not_configured",
    "storage_not_configured",
  ]);
}

test.describe("ISCY visuelle Regression", () => {
  for (const [name, route, requiresLogin] of pages) {
    test(name, async ({ page }, testInfo) => {
      if (requiresLogin) {
        await authenticate(page);
      }
      await page.goto(route, { waitUntil: "domcontentloaded" });
      await stabilize(page);
      await assertSafeUsablePage(page);
      if (route === "/evidence/integrity/") {
        await assertUnconfiguredEvidenceStorage(page);
      }
      if (
        process.env.ISCY_TEST_VISUAL_FORCE_DIFF === "1" &&
        name === "login" &&
        testInfo.project.name === "desktop-1440"
      ) {
        await page.addStyleTag({
          content: "body { outline: 12px solid rgb(255, 0, 255) !important; }",
        });
      }
      await expect(page).toHaveScreenshot(`${name}.png`, {
        fullPage: true,
      });
    });
  }
});
