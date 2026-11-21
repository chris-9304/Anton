// Optional browser smoke test. Start Vite first, then run npm run test:ui.
// PLAYWRIGHT_PATH and ANTON_BROWSER_EXECUTABLE allow reuse of local tooling.
const assert = require("node:assert/strict");
const { chromium } = require(process.env.PLAYWRIGHT_PATH || "playwright");
(async () => {
  const browser = await chromium.launch({
    headless: true,
    executablePath: process.env.ANTON_BROWSER_EXECUTABLE || undefined,
  });
  try {
    const page = await browser.newPage();
    const errors = [];
    page.on("pageerror", (error) => errors.push(error.message));
    await page.route("http://localhost:8080/api/**", async (route) => {
      const path = new URL(route.request().url()).pathname;
      const data = path.endsWith("/status")
        ? {
            ai_enabled: true,
            monitoring_enabled: true,
            monitoring_health: "ready",
            demo_mode: true,
            scan_count: 2,
            threats_blocked: 1,
            files_monitored: 1200000,
            heuristic_score: 98,
          }
        : path.endsWith("/detections")
          ? {
              detections: [
                {
                  kind: "honeytokentouched",
                  level: "critical",
                  confidence: 1,
                  timestamp: "now",
                  file_path: "/TestRun/.sys_config.dat",
                },
              ],
            }
          : path.endsWith("/scans")
            ? {
                scans: [
                  {
                    id: 1,
                    type: "Quick scan",
                    result: "Demo only — no files scanned",
                    timestamp: "2026-11-20",
                  },
                ],
              }
            : { logs: [] };
      await route.fulfill({ json: data });
    });
    await page.goto(process.env.ANTON_WEB_URL || "http://127.0.0.1:18765");
    const detection = page.getByText("Canary file changed");
    await detection.waitFor();
    assert.equal(
      await detection.evaluate((el) => getComputedStyle(el).color),
      "rgb(248, 113, 113)",
    );
    await page
      .getByRole("button", { name: "Scan Activity", exact: true })
      .click();
    await page.getByText("Quick scan", { exact: true }).waitFor();
    await page
      .getByText("Demo only — no files scanned", { exact: true })
      .waitFor();
    await page.setViewportSize({ width: 375, height: 812 });
    assert.equal(
      await page.evaluate(
        () => document.documentElement.scrollWidth > innerWidth,
      ),
      false,
      "mobile layout overflows",
    );
    await page.getByRole("button", { name: "Settings", exact: true }).click();
    await page.getByRole("checkbox").first().waitFor();
    await page.route("**/api/settings/ai", (route) =>
      route.fulfill({ status: 503, json: { error: "offline" } }),
    );
    await page.getByRole("checkbox").first().click();
    await page.getByRole("alert").waitFor();
    assert.equal(
      await page.getByRole("checkbox").first().isChecked(),
      true,
      "failed toggle changed confirmed value",
    );
    await page.keyboard.press("Tab");
    assert.equal(
      await page.evaluate(() => document.activeElement.tagName),
      "INPUT",
    );
    await page.getByRole("button", { name: "Dashboard", exact: true }).click();
    await page.route("**/api/status", (route) =>
      route.fulfill({ status: 503, json: {} }),
    );
    await page.reload();
    await page.getByRole("alert").waitFor();
    assert.deepEqual(errors, []);
    console.log(
      "Browser smoke checks passed: severity, scan fields, mobile layout, settings rollback, keyboard navigation, offline state.",
    );
  } finally {
    await browser.close();
  }
})().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
