import assert from "node:assert/strict";
import test from "node:test";
import { createSupportingTools, getScanResult, scanUrl } from "../public/webmcp.js";
const session = () => Response.json({ authenticated: true, csrf_token: "c".repeat(32), expires_at: "2026-09-01T13:00:00.000Z" });
const fetchEvidence = { requested_url: "https://example.com/", final_url: "https://example.com/", redirect_chain: [], validated_hops: [{ hostname: "example.com", address_count: 2 }] };
const receiptBody = (mode = "paste_url") => ({
  mode, scan_ids: ["a".repeat(32)], accepted_targets: 1, rejected_candidates: 0, truncated: false,
  unscannable_reason: null, fetch_evidence: mode === "paste_url" ? fetchEvidence : null });
const receipt = (mode = "paste_url") => Response.json(receiptBody(mode), { status: 201 });
const result = (scanId = "a".repeat(32), overrides = {}) => ({
  scan_id: scanId, mode: "paste_url", canonical_target: "https://example.com/", risk_label: "unknown",
  analysis_state: "unknown", confidence: "low", supporting_evidence: [], contradicting_evidence: [],
  provider_observations: [], limitations: ["No provider observation was available."], ...overrides });
test("supporting tools have literal bounded read-only untrusted contracts", async () => {
  const tools = createSupportingTools(async () => new Response());
  assert.deepEqual(tools.map(({ name }) => name), ["scan_url", "get_scan_result"]);
  for (const tool of tools) {
    assert.deepEqual(tool.annotations, { readOnlyHint: true, untrustedContentHint: true });
    assert.equal(tool.inputSchema.additionalProperties, false);
  }
  assert.deepEqual(tools[0].inputSchema.required, ["targetUrl"]);
  assert.equal(tools[0].inputSchema.properties.pastedHtml.maxLength, 200_000);
  assert.deepEqual(tools[1].inputSchema.required, ["scanId"]);
  assert.equal(tools[1].inputSchema.properties.scanId.pattern, "^[a-f0-9]{32}$");
  await assert.rejects(tools[0].execute({ targetUrl: "https://example.com", extra: true }), /invalid_arguments/);
  await assert.rejects(tools[1].execute({}), /invalid_arguments/);
});
test("scan_url uses authenticated URL and local-only HTML request shapes", async () => {
  for (const mode of ["url", "html"]) {
    const calls = [];
    const fetcher = async (path, init) => { calls.push({ path, init });
      return calls.length === 1 ? session() : receipt(`paste_${mode}`); };
    const output = JSON.parse(await scanUrl({ fetcher, targetUrl: "https://example.com/base/",
      providerConsent: true, ...(mode === "html"
        ? { pastedHtml: "<a href='./one'>One</a>" } : {}) }));
    assert.equal(output.mode, `paste_${mode}`);
    assert.deepEqual(JSON.parse(calls[1].init.body), mode === "url"
      ? { mode: "url", url: "https://example.com/base/" }
      : { mode: "html", html: "<a href='./one'>One</a>", base_url: "https://example.com/base/" });
    assert.equal(calls[1].path, "/api/scans/paste");
    assert.equal(calls[1].init.headers["x-watchdog-csrf"], "c".repeat(32));
    assert.equal(calls[1].init.headers["x-watchdog-provider-consent"], "google_safe_browsing");
    assert.equal(calls[1].init.credentials, "same-origin");
  }
});
test("get_scan_result is session-owned, typed, bounded and cancellable", async () => {
  const scanId = "a".repeat(32);
  const output = JSON.parse(await getScanResult({ scanId, fetcher: async (path, init) => {
      assert.equal(path, `/api/results/${scanId}`);
      assert.equal(init.credentials, "same-origin");
      return Response.json({ status: "ok", result: result(scanId) });
    } }));
  assert.equal(output.scan_id, scanId);
  await assert.rejects(getScanResult({
    scanId,
    fetcher: async () => Response.json({ error: "missing" }, { status: 404 }),
  }), /service_unavailable/);
  await assert.rejects(getScanResult({
    scanId, fetcher: async () => Response.json({ status: "ok", result: result("b".repeat(32)) }),
  }), /malformed_response/);
  await assert.rejects(getScanResult({ scanId: "raw-url", fetcher: async () => new Response() }),
    /invalid_arguments/);
  const controller = new AbortController();
  controller.abort();
  await assert.rejects(getScanResult({ scanId, fetcher: async () => new Response(), signal: controller.signal }),
    { name: "AbortError" });
  const late = new AbortController(); let release; const pending = getScanResult({ scanId, signal: late.signal, fetcher: async () => new Promise((resolve) => { release = resolve; }) });
  await new Promise((resolve) => setImmediate(resolve)); late.abort(); release(Response.json({ status: "ok", result: result(scanId) }));
  await assert.rejects(pending, { name: "AbortError" });
});
test("supporting tool outputs reject extra or unbounded fields and update the shared surface", async () => {
  const scanId = "a".repeat(32);
  const events = [];
  class CustomEvent { constructor(type, init) { this.type = type; this.detail = init.detail; } }
  const pageDocument = {
    defaultView: { CustomEvent }, dispatchEvent: (event) => events.push(event),
    querySelector: () => ({ checked: true }),
  };
  let calls = 0;
  const scanTool = createSupportingTools(async () => ++calls === 1 ? session() : receipt(), pageDocument)[0];
  await scanTool.execute({ targetUrl: "https://example.com/" });
  assert.equal(events[0].type, "watchdog:scan-receipt");
  const resultTool = createSupportingTools(async () =>
    Response.json({ status: "ok", result: result(scanId) }), pageDocument)[1];
  await resultTool.execute({ scanId });
  assert.equal(events[1].type, "watchdog:scan-result");
  for (const malformed of [
    { status: "ok", result: { ...result(scanId), attacker: "x".repeat(1_000_000) } },
    { status: "ok", result: result(scanId, { limitations: ["x".repeat(513)] }) },
    { status: "ok", result: result(scanId, { supporting_evidence: [{ source: "candidate:paste_url", target: "not-a-url", category: "misleading_url_like_text",
      observed_at: "2026-09-01T00:00:00.000Z", freshness: "fresh", reference: null }] }) },
    { status: "ok", result: result(scanId, { provider_observations: [{ provider: "google_safe_browsing", source: "fixture", queried_target: "https://example.com/",
      observed_at: "2026-09-01T00:00:00.000Z", expires_at: null, freshness: "unknown", state: "no_match", category: null, confidence: "low", reference: null, error: "timeout" }] }) },
  ]) await assert.rejects(getScanResult({ scanId, fetcher: async () => Response.json(malformed) }),
    /malformed_response/);
  for (const malformed of [{ ...receiptBody(), evil: "x" }, { ...receiptBody(), fetch_evidence: null },
    { ...receiptBody(), accepted_targets: Number.MAX_SAFE_INTEGER, truncated: true }]) {
    let scanCalls = 0; await assert.rejects(scanUrl({ targetUrl: "https://example.com/",
      fetcher: async () => ++scanCalls === 1 ? session() : Response.json(malformed) }), /malformed_response/);
  }
});
