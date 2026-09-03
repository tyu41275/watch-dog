export async function runJourney(page, expect) {
  await page.addInitScript(() => {
    globalThis.__watchdogTools = [];
    Object.defineProperty(document, "modelContext", { configurable: true, value: {
      async registerTool(tool, { signal }) {
        globalThis.__watchdogTools.push(tool.name);
        signal.addEventListener("abort", () => { globalThis.__watchdogTools = []; }, { once: true });
      },
    } });
  });
  await page.goto("/");
  await page.locator("input[name=username]").fill("incorrect-user");
  await page.locator("input[name=password]").fill("incorrect-password");
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.locator("#login-panel")).toBeVisible();

  await page.locator("input[name=username]").fill(process.env.WD_USER);
  await page.locator("input[name=password]").fill(process.env.WD_PASS);
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.locator("#scan-panel")).toBeVisible();
  const cookie = (await page.context().cookies()).find(({ name }) => name === "__Host-watchdog_session");
  expect(cookie?.secure).toBe(true); expect(cookie?.httpOnly).toBe(true);
  expect(cookie?.sameSite).toBe("Strict");

  await page.locator("input[name=base_url]").fill("https://watch.example/reference");
  await page.locator("textarea[name=html]").fill(
    '<a href="./guidance"><strong>plain evidence</strong></a>');
  await page.getByRole("button", { name: "Scan pasted HTML" }).click();
  await expect(page.locator("#app-status")).toContainText("provider_consent_required");
  await page.locator("#provider-consent").check();
  await page.getByRole("button", { name: "Scan pasted HTML" }).click();
  await expect(page.locator("#results")).toContainText("guidance");
  expect(await page.locator("#results strong").count()).toBe(0);

  await page.locator("input[name=url]").fill("http://127.0.0.1:9444/private");
  await page.getByRole("button", { name: "Scan URL" }).click();
  await expect(page.locator("#results")).toContainText("unscannable");

  const routeResponses = [];
  page.on("response", (response) => {
    if (response.url().includes("/reference")) routeResponses.push({
      status: response.status(), url: response.url() });
  });
  await page.goto("/reference.html?probe=1");
  await expect(page).toHaveURL("https://watch.example/reference");
  expect(routeResponses.some(({ status, url }) => status === 308 &&
    url.endsWith("/reference.html?probe=1"))).toBe(true);
  await expect(page.locator("#delayed-live-anchor")).toHaveCount(1);
  await page.getByRole("button", { name: "Inspect current rendered anchors" }).click();
  await expect(page.locator("#app-status")).toContainText("provider_consent_required");
  await page.locator("#provider-consent").check();
  await page.getByRole("button", { name: "Inspect current rendered anchors" }).click();
  await expect(page.locator("#results")).toContainText("delayed-evidence");
  await expect.poll(() => page.evaluate(() => globalThis.__watchdogTools)).toEqual([
    "inspect_current_page", "scan_url", "get_scan_result",
  ]);
  await page.getByRole("button", { name: "Sign out" }).click();
  await expect(page.locator("#login-panel")).toBeVisible();
  await expect(page.locator("#results")).toBeHidden();
}
