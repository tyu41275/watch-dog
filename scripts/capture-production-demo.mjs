import { chmod, mkdir, writeFile } from "node:fs/promises";
import { chromium } from "playwright";

class CaptureFailure extends Error {}

const required = (name) => {
  const value = process.env[name];
  if (typeof value !== "string" || value.length === 0) {
    throw new CaptureFailure(`missing_${name.toLowerCase()}`);
  }
  return value;
};

const base = new URL(required("WATCH_DOG_URL"));
const expectedRevision = required("EXPECTED_SHA");
const username = required("WATCH_DOG_JUDGE_USERNAME").trim();
const password = required("WATCH_DOG_JUDGE_PASSWORD");
const outputDirectory = process.env.CAPTURE_OUTPUT ?? "recordings/production";

if (base.protocol !== "https:" || base.pathname !== "/" || base.search || base.hash) {
  throw new CaptureFailure("invalid_capture_url");
}
if (!/^[a-f0-9]{40}$/u.test(expectedRevision) || username.length === 0) {
  throw new CaptureFailure("invalid_capture_configuration");
}

await mkdir(outputDirectory, { recursive: true });

const browser = await chromium.launch({
  headless: true,
  args: ["--enable-experimental-web-platform-features"],
});

const version = browser.version();
const major = Number.parseInt(version.split(".")[0] ?? "0", 10);
if (!Number.isSafeInteger(major) || major < 149) {
  throw new CaptureFailure("unsupported_chromium_version");
}

const pause = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds));

async function authenticateWithoutRecording() {
  const context = await browser.newContext({ viewport: { width: 1920, height: 1080 } });
  const page = await context.newPage();
  await page.goto(base.href, { waitUntil: "domcontentloaded" });
  await page.locator("input[name=username]").fill(username);
  await page.locator("input[name=password]").fill(password);
  await page.getByRole("button", { name: "Sign in" }).click();
  try {
    await page.locator("#scan-panel").waitFor({ state: "visible", timeout: 20_000 });
  } catch {
    throw new CaptureFailure("production_login_failed");
  }
  const cookies = await context.cookies(base.href);
  if (!cookies.some(({ name }) => name === "__Host-watchdog_session")) {
    throw new CaptureFailure("production_session_cookie_missing");
  }
  await context.close();
  return { cookies, origins: [] };
}

async function addCapturePresentation(page) {
  await page.addStyleTag({ content: `
    main { width: min(76rem, calc(100% - 3rem)); margin: 1.2rem auto; font-size: 20px; }
    h1 { margin-block: 0 .4rem; }
    #results { max-height: 48vh; overflow: auto; font-size: 16px; line-height: 1.35; }
    #capture-proof { position: fixed; z-index: 2147483647; top: 22px; right: 22px;
      width: 650px; padding: 18px 20px; border-radius: 14px; color: #f8fafc;
      background: rgba(5, 12, 24, .94); border: 2px solid #38bdf8;
      box-shadow: 0 18px 50px rgba(0,0,0,.35); white-space: pre-wrap;
      font: 600 19px/1.45 system-ui, sans-serif; pointer-events: none; }
    #capture-proof[data-tone="success"] { border-color: #4ade80; }
    #capture-proof[data-tone="action"] { border-color: #facc15; }
    #delayed-live-anchor.capture-highlight { outline: 5px solid #facc15; outline-offset: 5px; }
  ` });
  await page.evaluate(() => {
    const panel = document.createElement("div");
    panel.id = "capture-proof";
    panel.setAttribute("role", "status");
    panel.textContent = "Authentic production capture initializing…";
    document.body.append(panel);
  });
}

async function proof(page, title, lines, tone = "action") {
  await page.evaluate(({ title, lines, tone }) => {
    const panel = document.querySelector("#capture-proof");
    if (panel instanceof HTMLElement) {
      panel.dataset.tone = tone;
      panel.textContent = `${title}\n${lines.join("\n")}`;
    }
  }, { title, lines, tone });
}

async function saveRecordedContext(id, storageState, run) {
  const context = await browser.newContext({
    viewport: { width: 1920, height: 1080 },
    storageState,
    recordVideo: { dir: outputDirectory, size: { width: 1920, height: 1080 } },
  });
  const page = await context.newPage();
  const video = page.video();
  try {
    await run(page);
  } finally {
    await context.close();
  }
  if (video === null) throw new CaptureFailure(`missing_${id}_video`);
  await video.saveAs(`${outputDirectory}/${id}.webm`);
}

const revisionResponse = await fetch(new URL("/api/revision", base));
const revisionBody = await revisionResponse.json();
if (revisionResponse.status !== 200 || revisionBody?.revision !== expectedRevision) {
  throw new CaptureFailure("capture_revision_mismatch");
}

const storageState = await authenticateWithoutRecording();
const evidence = {
  schema_version: 1,
  generated_at: new Date().toISOString(),
  production_url: base.href,
  revision: expectedRevision,
  browser: { product: "Chromium", version, webmcp_minimum_met: true },
  authentication: "accepted_before_recording",
  credentials_or_cookies_preserved: false,
  clips: {},
};

await saveRecordedContext("02-live-scan", storageState, async (page) => {
  await page.goto(new URL("/reference", base).href, { waitUntil: "domcontentloaded" });
  await addCapturePresentation(page);
  const native = await page.evaluate(() => ({
    available: typeof document.modelContext === "object",
    methods: document.modelContext === undefined ? [] :
      Object.getOwnPropertyNames(Object.getPrototypeOf(document.modelContext)),
  }));
  if (!native.available || !native.methods.includes("getTools") ||
      !native.methods.includes("executeTool")) {
    throw new CaptureFailure("native_webmcp_unavailable");
  }
  await proof(page, "SUPPORTED BROWSER • REAL PRODUCTION", [
    `Chromium ${version}`,
    "Native document.modelContext is available",
    `Deployed revision ${expectedRevision.slice(0, 12)}`,
  ], "success");
  await pause(2_500);

  const before = await page.locator("#delayed-live-anchor").count();
  await proof(page, "INVOCATION-TIME DOM", [
    `Delayed anchor count before insertion: ${before}`,
    "Waiting for the page's post-load DOM mutation…",
  ]);
  await page.locator("#delayed-live-anchor").waitFor({ state: "attached", timeout: 10_000 });
  await page.locator("#delayed-live-anchor").evaluate((anchor) =>
    anchor.classList.add("capture-highlight"));
  const delayedHref = await page.locator("#delayed-live-anchor").getAttribute("href");
  await proof(page, "DELAYED ANCHOR OBSERVED", [
    "Count after insertion: 1",
    `Rendered href: ${delayedHref}`,
    "The link exists now; it was absent at page load.",
  ], "success");
  await pause(3_000);

  const tools = await page.evaluate(async () => (await document.modelContext.getTools())
    .map(({ name, title }) => ({ name, title })));
  const toolNames = tools.map(({ name }) => name);
  for (const name of ["inspect_current_page", "scan_url", "get_scan_result"]) {
    if (!toolNames.includes(name)) throw new CaptureFailure(`missing_native_tool_${name}`);
  }
  await proof(page, "NATIVE WebMCP DISCOVERY • getTools()", toolNames.map((name) => `✓ ${name}`),
    "success");
  await pause(4_000);

  let dialogSeen = false;
  page.once("dialog", async (dialog) => {
    dialogSeen = true;
    await pause(1_600);
    await dialog.accept();
  });
  await proof(page, "NATIVE WebMCP INVOCATION", [
    "executeTool( inspect_current_page, {} )",
    "Chrome mediates this registered tool call.",
  ]);
  const inspectText = await page.evaluate(async () => {
    const tool = (await document.modelContext.getTools())
      .find(({ name }) => name === "inspect_current_page");
    return document.modelContext.executeTool(tool, "{}");
  });
  if (!dialogSeen || typeof inspectText !== "string") {
    throw new CaptureFailure("native_inspect_invocation_failed");
  }
  const inspect = JSON.parse(inspectText);
  const scanId = inspect?.results?.find(({ scan_id: id }) => typeof id === "string")?.scan_id;
  const delayed = inspect?.targets?.some(({ canonical_url: target }) =>
    typeof target === "string" && target.endsWith("/delayed-evidence"));
  const misleading = inspect?.results?.some(({ supporting_evidence: items }) =>
    Array.isArray(items) && items.some(({ category }) => category === "misleading_anchor_text"));
  if (!/^[a-f0-9]{32}$/u.test(scanId ?? "") || !delayed || !misleading) {
    throw new CaptureFailure("native_inspect_evidence_incomplete");
  }
  await page.locator("#results").scrollIntoViewIfNeeded();
  await proof(page, "INSPECT RESULTS • SHARED WITH THE PAGE", [
    `Accepted targets: ${inspect.accepted_targets}`,
    `Rejected candidates: ${inspect.rejected_candidates}`,
    "✓ delayed-evidence found in the rendered DOM",
    "✓ misleading_anchor_text evidence returned",
  ], "success");
  await pause(7_000);

  await proof(page, "NATIVE WebMCP FOLLOW-UP", [
    `executeTool( get_scan_result, { scanId: •••${scanId.slice(-6)} } )`,
    "The opaque ID stays session-owned and expires.",
  ]);
  const resultText = await page.evaluate(async (scanId) => {
    const tool = (await document.modelContext.getTools())
      .find(({ name }) => name === "get_scan_result");
    return document.modelContext.executeTool(tool, JSON.stringify({ scanId }));
  }, scanId);
  if (typeof resultText !== "string") throw new CaptureFailure("native_get_result_failed");
  const result = JSON.parse(resultText);
  const returned = result?.results?.[0];
  if (returned?.scan_id !== scanId) throw new CaptureFailure("native_get_result_mismatch");
  await proof(page, "get_scan_result • VERIFIED", [
    `Mode: ${returned.mode}`,
    `Risk: ${returned.risk_label}`,
    `Analysis state: ${returned.analysis_state}`,
    "The page and browser received the same session-owned result.",
  ], "success");
  await pause(7_000);
  evidence.clips.live = {
    native_webmcp: true,
    discovered_tools: toolNames,
    invoked_tools: ["inspect_current_page", "get_scan_result"],
    delayed_anchor_before: before,
    delayed_anchor_after: 1,
    delayed_anchor_in_result: delayed,
    misleading_anchor_evidence: misleading,
    scan_id_preserved: false,
  };
});

await saveRecordedContext("03-paste-scan", storageState, async (page) => {
  await page.goto(base.href, { waitUntil: "domcontentloaded" });
  await addCapturePresentation(page);
  await proof(page, "AUTHENTICATED PASTE SCAN • PRODUCTION", [
    "Credentials were entered before recording began.",
    "Input is inert HTML; no pasted scripts are executed.",
    "Canonical targets may be checked with Google Safe Browsing.",
  ], "success");
  await pause(3_000);
  await page.locator("input[name=base_url]").fill("https://example.com/demo");
  await page.locator("textarea[name=html]").fill(
    '<a href="/account">Customer account</a> <a href="mailto:help@example.com">Help</a>');
  await pause(3_000);
  await page.locator("#provider-consent").check();
  await proof(page, "PASTE SCAN INPUT READY", [
    "Bounded base URL: https://example.com/demo",
    "One HTTP(S) link plus one rejected mail link",
    "Provider disclosure accepted for this invocation only.",
  ]);
  await pause(2_000);
  await page.getByRole("button", { name: "Scan pasted HTML" }).click();
  await page.locator("#results").waitFor({ state: "visible", timeout: 30_000 });
  const paste = JSON.parse(await page.locator("#results").textContent());
  const first = paste?.results?.[0];
  if (paste?.mode !== "paste_html" || first === undefined) {
    throw new CaptureFailure("paste_scan_result_missing");
  }
  await page.locator("#results").scrollIntoViewIfNeeded();
  await proof(page, "PASTE SCAN RESULT • SHARED PIPELINE", [
    `Risk label: ${first.risk_label}`,
    `Analysis state: ${first.analysis_state}`,
    `Confidence: ${first.confidence}`,
    `Provider state: ${first.provider_observations?.[0]?.state ?? "unavailable"}`,
    "A no-match is evidence—not a safety guarantee.",
  ], "success");
  await pause(11_000);
  evidence.clips.paste = {
    mode: paste.mode,
    risk_label: first.risk_label,
    analysis_state: first.analysis_state,
    confidence: first.confidence,
    provider: first.provider_observations?.[0]?.provider ?? null,
    provider_state: first.provider_observations?.[0]?.state ?? null,
    raw_input_preserved: false,
    scan_ids_preserved: false,
  };
});

await browser.close();
const evidencePath = `${outputDirectory}/capture-evidence.json`;
await writeFile(evidencePath, `${JSON.stringify(evidence, null, 2)}\n`, { mode: 0o600 });
await chmod(evidencePath, 0o600);
console.log("PRODUCTION_CAPTURE_PASS");
