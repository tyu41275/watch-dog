import assert from "node:assert/strict";
import test from "node:test";
import {
  WEBMCP_LIMITS,
  createInspectCurrentPageTool,
  createSupportingTools,
  registerBrowserTools,
} from "../public/webmcp.js";

const ID = "a".repeat(32);
function page(anchors = []) {
  return {
    URL: "https://watch.example/reference",
    baseURI: "https://watch.example/reference",
    defaultView: { confirm: () => true },
    querySelectorAll: (selector) => selector === "a[href]" ? anchors : [],
    querySelector: () => null,
  };
}
const anchor = (href, text) => ({ getAttribute: () => href, textContent: text });

test("all three tools delegate to one controller with literal bounded arguments", async () => {
  const calls = [];
  const controller = {
    scanLive: async (payload, options) => { calls.push(["live", payload, options]);
      return { mode: "live_page" }; },
    scanPaste: async (payload, options) => { calls.push(["paste", payload, options]);
      return { mode: payload.mode }; },
    getResult: async (id, options) => { calls.push(["result", id, options]);
      return { mode: "live_page" }; },
  };
  const document = page([anchor("./one", "One")]);
  const inspect = createInspectCurrentPageTool(document, undefined, controller);
  const [scan, result] = createSupportingTools(document, undefined, controller);
  assert.deepEqual([inspect.name, scan.name, result.name],
    ["inspect_current_page", "scan_url", "get_scan_result"]);
  for (const tool of [inspect, scan, result]) {
    assert.equal(tool.inputSchema.additionalProperties, false);
    assert.deepEqual(tool.annotations, { readOnlyHint: true, untrustedContentHint: true });
  }

  await inspect.execute({});
  await scan.execute({ targetUrl: "https://example.test/" });
  await scan.execute({ targetUrl: "https://example.test/", pastedHtml: "<a>x</a>" });
  await result.execute({ scanId: ID });
  assert.deepEqual(calls.map(([kind]) => kind), ["live", "paste", "paste", "result"]);
  assert.equal(calls[0][1].candidates[0].raw_href, "./one");
  assert.deepEqual(calls[1][1], { mode: "url", url: "https://example.test/" });
  assert.deepEqual(calls[2][1], { mode: "html", html: "<a>x</a>",
    base_url: "https://example.test/" });
  assert.ok(calls.slice(0, 3).every(([, , options]) => options.consent === true));
});

test("invalid optional argument types and bounds reject before controller entry", async () => {
  const calls = [];
  const controller = {
    scanPaste: async (...args) => { calls.push(args); },
    getResult: async (...args) => { calls.push(args); },
  };
  const [scan, result] = createSupportingTools(page(), undefined, controller);
  for (const value of [
    {},
    { targetUrl: null },
    { targetUrl: 7 },
    { targetUrl: [] },
    { targetUrl: {} },
    { targetUrl: "https://example.test", extra: true },
    { targetUrl: "x".repeat(WEBMCP_LIMITS.maxHrefChars + 1) },
    { targetUrl: "https://example.test", pastedHtml: null },
    { targetUrl: "https://example.test", baseUrl: "https://base.test" },
  ]) await assert.rejects(scan.execute(value), /invalid_arguments/u);
  for (const value of [null, 7, [], {}, { scanId: null }, { scanId: "short" },
    { scanId: ID, extra: true }]) {
    await assert.rejects(result.execute(value), /invalid_arguments/u);
  }
  assert.deepEqual(calls, []);
});

test("provider consent is evaluated independently on every scan invocation", async () => {
  let confirmations = 0;
  const document = page();
  document.defaultView.confirm = () => { confirmations += 1; return confirmations === 2; };
  const controller = { scanPaste: async (_payload, options) => {
    if (!options.consent) throw new Error("provider_consent_required");
    return { mode: "paste_url" };
  } };
  const [scan] = createSupportingTools(document, undefined, controller);
  await assert.rejects(scan.execute({ targetUrl: "https://example.test" }),
    /provider_consent_required/u);
  await scan.execute({ targetUrl: "https://example.test" });
  assert.equal(confirmations, 2);
});

test("native registration shares one abort scope and cleans partial registration", async () => {
  const success = page();
  const registered = [];
  success.modelContext = { registerTool: async (tool, options) => {
    registered.push([tool.name, options.signal]);
  } };
  const registration = await registerBrowserTools(success, async () => {});
  assert.deepEqual(registered.map(([name]) => name),
    ["inspect_current_page", "scan_url", "get_scan_result"]);
  assert.ok(registered.every(([, signal]) => signal === registration.signal && !signal.aborted));
  registration.abort();
  assert.ok(registered.every(([, signal]) => signal.aborted));

  const partial = page();
  const partialSignals = [];
  let count = 0;
  partial.modelContext = { registerTool: async (_tool, { signal }) => {
    partialSignals.push(signal);
    if (++count === 2) throw new Error("registration unavailable");
  } };
  await assert.rejects(registerBrowserTools(partial, async () => {}),
    /registration unavailable/u);
  assert.ok(partialSignals.every((signal) => signal.aborted));
});

test("UI sources route through the controller and keep output inert", async () => {
  const app = await import("node:fs/promises").then((fs) =>
    fs.readFile(new URL("../public/app.js", import.meta.url), "utf8"));
  const html = await import("node:fs/promises").then((fs) => Promise.all([
    fs.readFile(new URL("../public/index.html", import.meta.url), "utf8"),
    fs.readFile(new URL("../public/reference.html", import.meta.url), "utf8"),
  ]));
  assert.match(app, /sessionClientFor\(document\)/u);
  assert.doesNotMatch(app, /\bfetch\s*\(/u);
  assert.doesNotMatch(app, /innerHTML|insertAdjacentHTML/u);
  assert.match(app, /output\.textContent/u);
  for (const source of html) {
    assert.match(source, /provider-consent/u);
    assert.match(source, /app\.js/u);
  }
});
