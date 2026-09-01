import { expect, test } from "@playwright/test";
import { judge, scanPastedHtml, signIn } from "./journey.mjs";
test("real Worker and browser seam completes the protected two-mode journey", async ({ page, context }) => {
  const registered = [];
  await page.addInitScript(() => {
    globalThis.__watchDogTools = [];
    globalThis.__watchDogShimmedWebMcp = document.modelContext === undefined;
    if (globalThis.__watchDogShimmedWebMcp) Object.defineProperty(Document.prototype, "modelContext", {
      configurable: true, get: () => ({ registerTool: async (tool) => globalThis.__watchDogTools.push(tool) }),
    });
  });
  await page.goto("/"); await page.getByLabel("Username").fill("wrong"); await page.getByLabel("Password").fill("wrong");
  await page.getByRole("button", { name: "Sign in" }).click(); await expect(page.locator("#app-status")).toHaveText("invalid_credentials");
  await page.getByLabel("Username").fill(judge.username); await page.getByLabel("Password").fill(judge.password);
  const loginResponse = page.waitForResponse((response) => response.url().endsWith("/api/login")); await page.getByRole("button", { name: "Sign in" }).click();
  expect((await loginResponse).status()).toBe(200);
  await expect(page.locator("#scan-panel")).toBeVisible();
  const cookie = (await context.cookies()).find(({ name }) => name === "__Host-watchdog_session");
  expect(cookie).toMatchObject({ httpOnly: true, secure: true, sameSite: "Strict" });
  await expect(page.locator(".provider-disclosure")).toContainText("Google Safe Browsing");
  await expect(page.locator(".provider-disclosure a")).toHaveCount(2);
  await page.getByLabel("Effective base URL").fill("https://example.com/base/"); await page.getByLabel("HTML").fill("<a href='./consent'>Consent gate</a>");
  await page.getByRole("button", { name: "Scan inert HTML" }).click();
  await expect(page.locator("#app-status")).toHaveText("provider_consent_required");
  await page.evaluate(() => { globalThis.__watchDogXss = 0; });
  await scanPastedHtml(page, `<a href="./same#one">First</a><a href="./same#two">Second</a>
    <a href="mailto:x@example.com">Mail</a><a href="https://example.com/?q=%3Csvg%20onload%3Dalert(1)%3E">Hostile</a>
    <img src="/must-not-load" onerror="globalThis.__watchDogXss=1">`);
  await expect(page.locator(".result-card")).toHaveCount(3); await expect(page.locator(".result-card").first()).toContainText("provider_error");
  await expect(page.locator(".result-grid")).toContainText("not_configured");
  await expect(page.locator(".result-grid")).not.toContainText(/\bsafe\b/ui);
  expect(await page.evaluate(() => globalThis.__watchDogXss)).toBe(0); expect(await page.locator("#results img, #results svg, #results script").count()).toBe(0);
  await page.evaluate(async () => {
    const { renderResults } = await import("/results.js");
    globalThis.__renderProvider = (source) => { const target = "https://example.com/";
      const observed_at = "2026-09-01T00:00:00.000Z"; const expires_at = "2026-09-01T00:01:00.000Z";
      const reference = source === "live" ? "https://transparencyreport.google.com/safe-browsing/search" : "fixture";
      renderResults(document.querySelector("#results"), [{ scan_id: "f".repeat(32), mode: "paste_url",
        canonical_target: target, risk_label: "known_malicious", analysis_state: "complete", confidence: "medium",
        supporting_evidence: [{ source: `${source}:google_safe_browsing`, target, category: "malware", observed_at,
          freshness: "fresh", reference }], contradicting_evidence: [], limitations: [], provider_observations: [{
          provider: "google_safe_browsing", source, queried_target: target, observed_at, expires_at,
          freshness: "fresh", state: "match", category: "malware", confidence: "medium", reference, error: null }],
      }]); }; globalThis.__renderProvider("fixture");
  });
  await expect(page.locator(".result-card")).not.toContainText("Advisory provided by Google"); await page.evaluate(() => globalThis.__renderProvider("live"));
  await expect(page.locator(".result-card")).toContainText("Advisory provided by Google"); await expect(page.locator(".result-card")).toContainText("https://transparencyreport.google.com/safe-browsing/search");
  await page.getByLabel("HTTP(S) URL").fill("http://127.0.0.1/");
  await page.getByRole("button", { name: "Scan URL" }).click(); await expect(page.locator(".result-card").first()).toContainText("unscannable");
  let releaseResult;
  const held = new Promise((resolve) => { releaseResult = resolve; });
  await page.route("**/api/results/*", async (route) => {
    await held;
    const scanId = route.request().url().split("/").at(-1);
    await route.fulfill({ json: { status: "ok", result: { scan_id: scanId,
      canonical_target: "https://stale.example/", risk_label: "unknown", analysis_state: "unknown",
      confidence: "low", supporting_evidence: [], contradicting_evidence: [],
      provider_observations: [], limitations: [] } } });
  });
  const staleRequest = page.waitForRequest((request) => request.url().includes("/api/results/"));
  await page.getByRole("button", { name: "Scan URL" }).click();
  await staleRequest; await page.getByRole("button", { name: "Sign out" }).click();
  await expect(page.locator("#login-panel")).toBeVisible();
  releaseResult(); await page.waitForTimeout(50);
  await expect(page.locator("#results")).toBeHidden();
  await page.unroute("**/api/results/*"); await signIn(page);
  await page.goto("/reference"); await page.locator("#provider-consent").check();
  const before = await page.locator("#reference-links a").count(); await expect(page.locator("#delayed-live-anchor")).toBeVisible();
  expect(await page.locator("#reference-links a").count()).toBe(before + 1);
  const shimmed = await page.evaluate(() => globalThis.__watchDogShimmedWebMcp);
  if (shimmed) await expect.poll(() => page.evaluate(() => globalThis.__watchDogTools.map(({ name }) => name)))
    .toEqual(["inspect_current_page", "scan_url", "get_scan_result"]);
  else await expect(page.locator("#webmcp-status")).toContainText("WebMCP tools registered");
  const liveRequest = page.waitForRequest((request) => request.url().endsWith("/api/scans/live"));
  if (shimmed) await page.evaluate(() => globalThis.__watchDogTools
    .find(({ name }) => name === "inspect_current_page").execute({}));
  else await page.getByRole("button", { name: "Inspect current rendered anchors" }).click();
  const liveBody = JSON.parse((await liveRequest).postData()); expect(liveBody.candidates.some(({ raw_href }) => raw_href === "./delayed-evidence")).toBe(true);
  expect(await page.locator("#delayed-live-anchor").evaluate((anchor) => anchor.href))
    .toBe(`${new URL(page.url()).origin}/delayed-evidence`);
  await expect(page.locator(".result-grid")).toContainText("disallowed_port"); await expect(page.locator(".result-grid")).toContainText("unsupported_scheme");
  await expect(page.locator(".result-grid")).toContainText("misleading_url_like_text");
  if (shimmed) {
    registered.push(...await page.evaluate(() => globalThis.__watchDogTools.map((tool) => ({
      name: tool.name, schema: tool.inputSchema, annotations: tool.annotations,
    }))));
    expect(registered.every(({ annotations }) =>
      annotations.readOnlyHint && annotations.untrustedContentHint)).toBe(true);
    expect(registered.find(({ name }) => name === "inspect_current_page").schema.additionalProperties).toBe(false);
    const scanId = await page.evaluate(async () => JSON.parse(await globalThis.__watchDogTools
      .find(({ name }) => name === "scan_url").execute({ targetUrl: "http://127.0.0.1/" })).scan_ids[0]);
    await expect(page.locator(".result-card").first()).toContainText("unscannable");
    await page.evaluate((id) => globalThis.__watchDogTools
      .find(({ name }) => name === "get_scan_result").execute({ scanId: id }), scanId);
    await expect(page.locator(".result-card").first()).toHaveAttribute("data-scan-id", scanId);
    await page.evaluate(async () => { const state = await fetch("/api/session").then((response) => response.json()); await fetch("/api/logout", { method: "POST", headers: { "x-watchdog-csrf": state.csrf_token } });
      document.dispatchEvent(new CustomEvent("watchdog:scan-result", { detail: { scan_id: "e".repeat(32) } })); }); await expect(page.locator("#results")).toBeHidden();
  }
});
