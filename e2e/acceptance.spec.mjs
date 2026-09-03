import { test, expect } from "@playwright/test";
import { runJourney } from "./journey.mjs";

if (process.env.WD_CONTROLLED_FAILURE === "1") {
  test("controlled-artifact probe retains bounded failure evidence", async ({ page }) => {
    await page.goto("/");
    await expect(page.locator("#results")).toHaveAttribute("data-controlled-probe", "present",
      { timeout: 1_000 });
  });
} else {
  test("real Wrangler HTTPS preserves the complete session and browser journey", async ({ page }) => {
    await runJourney(page, expect);
  });

  test("native partial registration aborts the shared tool scope atomically", async ({ page }) => {
  await page.addInitScript(() => {
    globalThis.__watchdogTools = [];
    Object.defineProperty(document, "modelContext", { configurable: true, value: {
      async registerTool(tool, { signal }) {
        signal.addEventListener("abort", () => { globalThis.__watchdogTools = []; }, { once: true });
        if (globalThis.__watchdogTools.length === 1) throw new Error("registration unavailable");
        globalThis.__watchdogTools.push(tool.name);
      },
    } });
  });
  await page.goto("/");
  await expect(page.locator("#webmcp-status")).toContainText("registration failed");
    await expect.poll(() => page.evaluate(() => globalThis.__watchdogTools)).toEqual([]);
  });
}
