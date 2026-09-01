import { expect, test } from "@playwright/test";
import { judge, scanPastedHtml, signIn } from "./journey.mjs";

test("real Worker and browser seam completes the protected two-mode journey", async ({ page, context }) => {
  const registered = [];
  await page.addInitScript(() => {
    globalThis.__watchDogTools = [];
    Object.defineProperty(Document.prototype, "modelContext", {
      configurable: true,
      get: () => ({ registerTool: async (tool) => globalThis.__watchDogTools.push(tool) }),
    });
  });

  await page.goto("/");
  await page.getByLabel("Username").fill("wrong");
  await page.getByLabel("Password").fill("wrong");
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.locator("#app-status")).toHaveText("invalid_credentials");
  await page.getByLabel("Username").fill(judge.username);
  await page.getByLabel("Password").fill(judge.password);
  const loginResponse = page.waitForResponse((response) => response.url().endsWith("/api/login"));
  await page.getByRole("button", { name: "Sign in" }).click();
  expect((await loginResponse).status()).toBe(200);
  await expect(page.locator("#scan-panel")).toBeVisible();
  const cookie = (await context.cookies()).find(({ name }) => name === "__Host-watchdog_session");
  expect(cookie).toMatchObject({ httpOnly: true, secure: true, sameSite: "Strict" });

  await page.evaluate(() => { globalThis.__watchDogXss = 0; });
  await scanPastedHtml(page, `<a href="./same#one">First</a><a href="./same#two">Second</a>
    <a href="mailto:x@example.com">Mail</a><a href="https://example.com/?q=%3Csvg%20onload%3Dalert(1)%3E">Hostile</a>
    <img src="/must-not-load" onerror="globalThis.__watchDogXss=1">`);
  await expect(page.locator(".result-card")).toHaveCount(3);
  await expect(page.locator(".result-card").first()).toContainText("provider_error");
  await expect(page.locator(".result-grid")).toContainText("not_configured");
  await expect(page.locator(".result-grid")).not.toContainText(/\bsafe\b/ui);
  expect(await page.evaluate(() => globalThis.__watchDogXss)).toBe(0);
  expect(await page.locator("#results img, #results svg, #results script").count()).toBe(0);

  await page.getByLabel("HTTP(S) URL").fill("http://127.0.0.1/");
  await page.getByRole("button", { name: "Scan URL" }).click();
  await expect(page.locator(".result-card").first()).toContainText("unscannable");

  await page.goto("/reference");
  const before = await page.locator("#reference-links a").count();
  await expect(page.locator("#delayed-live-anchor")).toBeVisible();
  expect(await page.locator("#reference-links a").count()).toBe(before + 1);
  await expect.poll(() => page.evaluate(() => globalThis.__watchDogTools.map(({ name }) => name)))
    .toEqual(["inspect_current_page", "scan_url", "get_scan_result"]);
  const liveRequest = page.waitForRequest((request) => request.url().endsWith("/api/scans/live"));
  await page.evaluate(() => globalThis.__watchDogTools
    .find(({ name }) => name === "inspect_current_page").execute({}));
  const liveBody = JSON.parse((await liveRequest).postData());
  expect(liveBody.candidates.some(({ raw_href }) => raw_href === "./delayed-evidence")).toBe(true);
  expect(await page.locator("#delayed-live-anchor").evaluate((anchor) => anchor.href))
    .toBe(`${new URL(page.url()).origin}/delayed-evidence`);
  await expect(page.locator(".result-grid")).toContainText("disallowed_port");
  await expect(page.locator(".result-grid")).toContainText("unsupported_scheme");
  await expect(page.locator(".result-grid")).toContainText("misleading_url_like_text");

  registered.push(...await page.evaluate(() => globalThis.__watchDogTools.map((tool) => ({
    name: tool.name, schema: tool.inputSchema, annotations: tool.annotations,
  }))));
  expect(registered.every(({ annotations }) =>
    annotations.readOnlyHint && annotations.untrustedContentHint)).toBe(true);
  expect(registered.find(({ name }) => name === "inspect_current_page").schema.additionalProperties).toBe(false);
});
