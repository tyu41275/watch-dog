import { expect, test } from "@playwright/test";
import { runAssertedJourney } from "./journey.mjs";

test("real default-port Worker browser seam completes the protected two-mode journey", async ({ page, context }) => {
  await runAssertedJourney(page, context);
});

test("browser auto-registration aborts all partial registrations", async ({ page }) => {
  await page.addInitScript(() => {
    globalThis.__watchDogAttempts = [];
    Object.defineProperty(Document.prototype, "modelContext", { configurable: true,
      get: () => ({ registerTool: async (tool, options) => {
        globalThis.__watchDogAttempts.push({ tool, signal: options.signal });
        if (globalThis.__watchDogAttempts.length === 2) throw new Error("synthetic registration failure");
      } }) });
  });
  await page.goto("https://watch.example/");
  await expect(page.locator("#webmcp-status"))
    .toHaveText("WebMCP registration failed; no tools are claimed available.");
  expect(await page.evaluate(() => ({
    attempts: globalThis.__watchDogAttempts.length,
    same: globalThis.__watchDogAttempts.every(({ signal }) =>
      signal === globalThis.__watchDogAttempts[0].signal),
    aborted: globalThis.__watchDogAttempts.every(({ signal }) => signal.aborted),
  }))).toEqual({ attempts: 2, same: true, aborted: true });
});
