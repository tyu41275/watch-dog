import { expect } from "@playwright/test";

const judge = { username: "playwright-judge", password: "synthetic-browser-fixture" };
const origin = "https://watch.example";

async function visibleOutput(page) {
  await expect(page.locator("#results")).toBeVisible();
  return page.locator("#results").evaluate((node) => JSON.parse(node.textContent));
}

async function signIn(page) {
  await page.getByLabel("Username").fill(judge.username);
  await page.getByLabel("Password").fill(judge.password);
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.locator("#scan-panel")).toBeVisible();
}

function assertResultShape(output) {
  expect(output.results.length).toBeGreaterThan(0);
  for (const result of output.results) {
    expect(["known_malicious", "suspicious", "no_known_match", "unknown"]).toContain(result.risk_label);
    expect(["complete", "unknown", "unscannable", "provider_error", "stale", "conflicting"])
      .toContain(result.analysis_state);
    expect(["high", "medium", "low"]).toContain(result.confidence);
    expect(Array.isArray(result.supporting_evidence)).toBe(true);
    expect(Array.isArray(result.contradicting_evidence)).toBe(true);
    expect(Array.isArray(result.provider_observations)).toBe(true);
    expect(Array.isArray(result.limitations)).toBe(true);
    expect(result.risk_label).not.toBe("safe");
  }
}

async function holdNextResult(context, page) {
  const session = await context.newCDPSession(page);
  await session.send("Fetch.enable", { patterns: [{
    urlPattern: "*://watch.example/api/results/*", requestStage: "Response",
  }] });
  let resolve;
  const paused = new Promise((done) => { resolve = done; });
  session.on("Fetch.requestPaused", (event) => {
    if (event.responseStatusCode !== undefined) resolve(event);
  });
  return { paused, async release(event) {
    await session.send("Fetch.continueResponse", { requestId: event.requestId }).catch(() => {});
    await session.send("Fetch.disable").catch(() => {});
    await session.detach().catch(() => {});
  } };
}

async function invoke(page, name, argumentsObject, withSignal = false) {
  return page.evaluate(async ({ name, argumentsObject, withSignal }) => {
    const tool = globalThis.__watchDogTools.find((value) => value.name === name);
    const controller = withSignal ? new AbortController() : null;
    if (controller !== null) globalThis.__watchDogInvocationController = controller;
    try {
      return await tool.execute(argumentsObject, controller === null ? {} : { signal: controller.signal });
    } catch (error) {
      if (withSignal) return { errorName: error.name };
      throw error;
    }
  }, { name, argumentsObject, withSignal });
}

export async function runAssertedJourney(page, context, hooks = {}) {
  const pageRequests = [];
  page.on("request", (request) => pageRequests.push(request.url()));
  await page.addInitScript(() => {
    globalThis.__watchDogTools = [];
    Object.defineProperty(Document.prototype, "modelContext", { configurable: true,
      get: () => ({ registerTool: async (tool, options) => {
        globalThis.__watchDogTools.push(tool);
        globalThis.__watchDogRegistrationSignal = options.signal;
      } }) });
    globalThis.__watchDogPayloadRan = 0;
  });

  await page.goto(`${origin}/`);
  await page.getByLabel("Username").fill("wrong");
  await page.getByLabel("Password").fill("wrong");
  const denied = page.waitForResponse((response) => response.url() === `${origin}/api/login`);
  await page.getByRole("button", { name: "Sign in" }).click();
  expect((await denied).status()).toBe(401);
  await expect(page.locator("#app-status")).toHaveText("unauthorized");
  await expect(page.locator("#scan-panel")).toBeHidden();
  await signIn(page);
  const cookie = (await context.cookies(origin)).find(({ name }) => name === "__Host-watchdog_session");
  expect(cookie).toMatchObject({ httpOnly: true, secure: true, sameSite: "Strict" });

  let pastePosts = 0;
  page.on("request", (request) => {
    if (request.method() === "POST" && request.url() === `${origin}/api/scans/paste`) pastePosts += 1;
  });
  await page.getByLabel("Effective base URL").fill("https://source.example/base/");
  await page.getByLabel("Inert HTML").fill('<a href="./consent">Consent</a>');
  await page.getByRole("button", { name: "Scan pasted HTML" }).click();
  await expect(page.locator("#app-status")).toHaveText("provider_consent_required");
  expect(pastePosts).toBe(0);

  const hostile = `<a href="./same#one">First</a><a href="./same#two">Second</a>
    <a href="mailto:help@example.com">Mail</a>
    <a href="https://accounts.example.invalid/login">https://accounts.example.com/login</a>
    <img src="/must-not-load" onerror="globalThis.__watchDogPayloadRan=1">
    <script>globalThis.__watchDogPayloadRan=1</script>`;
  await page.locator("#provider-consent").check();
  await page.getByLabel("Inert HTML").fill(hostile);
  await page.getByRole("button", { name: "Scan pasted HTML" }).click();
  const paste = await visibleOutput(page);
  expect(paste.mode).toBe("paste_html");
  expect(paste.receipt.targets.find((target) => target.canonical_url === "https://source.example/base/same")
    .occurrences.map(({ occurrence_index }) => occurrence_index)).toEqual([0, 1]);
  expect(paste.receipt.rejections.some(({ reason }) => reason === "unsupported_scheme")).toBe(true);
  assertResultShape(paste);
  expect(paste.results.some(({ analysis_state }) => analysis_state === "provider_error")).toBe(true);
  expect(paste.results.some(({ supporting_evidence }) =>
    supporting_evidence.some(({ category }) => category === "misleading_url_like_text"))).toBe(true);
  expect(paste.results.every(({ provider_observations }) =>
    provider_observations.every(({ state, error }) => state === "not_configured" && error === "not_configured"))).toBe(true);
  expect(await page.locator("#results").evaluate((node) => node.children.length)).toBe(0);
  expect(await page.evaluate(() => globalThis.__watchDogPayloadRan)).toBe(0);
  await hooks.afterPaste?.(page, paste);

  await page.getByLabel("HTTP(S) URL").fill("http://127.0.0.1/");
  await page.getByRole("button", { name: "Scan URL" }).click();
  const unsafe = await visibleOutput(page);
  assertResultShape(unsafe);
  expect(unsafe.results[0].canonical_target).toBeNull();
  expect(unsafe.results[0].analysis_state).toBe("unscannable");
  expect(unsafe.results[0].limitations.join(" ")).toContain("unsafe_address");

  const staleHold = await holdNextResult(context, page);
  await page.getByRole("button", { name: "Scan URL" }).click();
  const staleEvent = await staleHold.paused;
  await page.getByRole("button", { name: "Sign out" }).click();
  await expect(page.locator("#login-panel")).toBeVisible();
  await staleHold.release(staleEvent);
  await expect(page.locator("#results")).toBeHidden();
  await expect(page.locator("#url-form button")).toBeEnabled();
  await signIn(page);

  const documents = [];
  const responseListener = (response) => {
    if (response.request().resourceType() === "document" && new URL(response.url()).origin === origin) {
      documents.push(response);
    }
  };
  page.on("response", responseListener);
  await page.goto(`${origin}/reference.html?probe=1`);
  page.off("response", responseListener);
  expect(documents.map((response) => [response.status(), response.url()])).toEqual([
    [308, `${origin}/reference.html?probe=1`], [200, `${origin}/reference`],
  ]);
  expect(documents.some((response) => response.status() === 307)).toBe(false);
  expect(documents[1].headers()["content-type"]).toContain("text/html");
  await expect(page).toHaveURL(`${origin}/reference`);
  await expect(page.getByRole("heading", { name: "Watch Dog-owned reference page" })).toBeVisible();
  await expect(page.locator("#delayed-live-anchor")).toHaveCount(0);
  await expect(page.locator("#delayed-live-anchor")).toBeVisible();
  await expect(page.locator("#scan-panel")).toBeVisible();
  await page.locator("#provider-consent").check();
  await expect.poll(() => page.evaluate(() => globalThis.__watchDogTools.map(({ name }) => name)))
    .toEqual(["inspect_current_page", "scan_url", "get_scan_result"]);
  const tools = await page.evaluate(() => globalThis.__watchDogTools.map(({ name, inputSchema, annotations }) =>
    ({ name, inputSchema, annotations })));
  expect(tools.every(({ annotations }) => JSON.stringify(annotations) ===
    JSON.stringify({ readOnlyHint: true, untrustedContentHint: true }))).toBe(true);
  expect(tools[0].inputSchema).toEqual({ type: "object", properties: {}, additionalProperties: false });
  expect(tools[1].inputSchema).toEqual({ type: "object", properties: {
    targetUrl: { type: "string", maxLength: 2048 },
    pastedHtml: { type: "string", maxLength: 200000 },
    baseUrl: { type: "string", maxLength: 2048 },
  }, required: ["targetUrl"], additionalProperties: false });
  expect(tools[2].inputSchema).toEqual({ type: "object", properties: {
    scanId: { type: "string", pattern: "^[a-f0-9]{32}$" },
  }, required: ["scanId"], additionalProperties: false });

  const beforeDismiss = pastePosts;
  page.once("dialog", (dialog) => dialog.dismiss());
  expect(await invoke(page, "scan_url", { targetUrl: "https://example.com/" }).catch((error) => error.message))
    .toContain("provider_consent_required");
  expect(pastePosts).toBe(beforeDismiss);
  let acceptedDialogs = 0;
  page.on("dialog", (dialog) => { acceptedDialogs += 1; void dialog.accept(); });
  const liveRequest = page.waitForRequest((request) => request.url() === `${origin}/api/scans/live`);
  const liveText = await invoke(page, "inspect_current_page", {});
  const liveBody = (await liveRequest).postDataJSON();
  expect(liveBody.document_url).toBe(`${origin}/reference`);
  expect(liveBody.candidates.some(({ raw_href }) => raw_href === "./delayed-evidence")).toBe(true);
  const live = JSON.parse(liveText);
  expect(live.targets.some(({ canonical_url }) => canonical_url === `${origin}/delayed-evidence`)).toBe(true);
  expect(await visibleOutput(page)).toEqual(live);
  await hooks.afterLive?.(page, live);

  const scanText = await invoke(page, "scan_url", { targetUrl: "http://127.0.0.1/" });
  const toolScan = JSON.parse(scanText);
  expect(await visibleOutput(page)).toEqual(toolScan);
  const scanId = toolScan.results[0].scan_id;
  const getText = await invoke(page, "get_scan_result", { scanId });
  expect(await visibleOutput(page)).toEqual(JSON.parse(getText));

  const abortHold = await holdNextResult(context, page);
  const abortCall = invoke(page, "scan_url", { targetUrl: "http://127.0.0.1/" }, true);
  const abortEvent = await abortHold.paused;
  await page.evaluate(() => globalThis.__watchDogInvocationController.abort(
    new DOMException("operator abort", "AbortError")));
  expect(await abortCall).toEqual({ errorName: "AbortError" });
  await abortHold.release(abortEvent);
  await expect(page.locator("#results")).toBeHidden();
  await expect(page.getByRole("heading", { name: "Watch Dog-owned reference page" })).toBeVisible();
  const recovery = JSON.parse(await invoke(page, "scan_url", { targetUrl: "http://127.0.0.1/" }));
  expect(await visibleOutput(page)).toEqual(recovery);
  expect(acceptedDialogs).toBe(4);

  expect(pageRequests.every((value) => new URL(value).origin === origin)).toBe(true);
  expect(pageRequests.every((value) => !value.includes(":8787"))).toBe(true);
}
