import assert from "node:assert/strict";
import test from "node:test";
import { SessionClient } from "../public/session-client.js";
const id = "a".repeat(32); const session = () => Response.json({ authenticated: true,
  csrf_token: "c".repeat(32), expires_at: "2026-09-01T13:00:00.000Z" });
const result = (scanId = id) => ({ kind: "analyzed", scan_id: scanId, mode: "paste_html",
  canonical_target: "https://example.com/", unscannable_reason: null, outcome: "unknown",
  risk_label: "unknown", analysis_state: "unknown", confidence: "low", supporting_evidence: [],
  contradicting_evidence: [], provider_observations: [],
  limitation_codes: ["no_provider_observation", "confidence_basis"] }); const receipt = () => Response.json({ mode: "paste_html", scan_ids: [id], accepted_targets: 1,
  rejected_candidates: 0, truncated: false, unscannable_reason: null }, { status: 201 });
test("one controller owns consent, decoding, final reauth, and commit", async () => {
  const calls = []; const commits = [];
  const client = new SessionClient(async (path, init) => { calls.push({ path, init }); if (path === "/api/session") return session();
    if (path === "/api/scans/paste") return receipt();
    return Response.json({ status: "ok", result: result() }); });
  client.connect({ commit: (display) => commits.push(display) }); await assert.rejects(
    client.scanPaste({ mode: "html", html: "<a>x</a>", base_url: "https://example.com/" },
    { consent: false }), /provider_consent_required/);
  assert.equal(calls.length, 0); const output = await client.scanPaste(
    { mode: "html", html: "<a>x</a>", base_url: "https://example.com/" },
    { consent: true });
  assert.equal(output.results[0].risk, "unknown"); assert.equal(commits.length, 1);
  assert.deepEqual(calls.map(({ path }) => path), ["/api/session", "/api/scans/paste", `/api/results/${id}`, "/api/session"]);
  assert.equal(calls[1].init.headers["x-watchdog-provider-consent"], "google_safe_browsing");
}); test("failed logout and auth loss synchronously invalidate and never disclose stale output", async () => {
  let release; const invalidations = []; const commits = []; const client = new SessionClient(async (path) => path === "/api/logout"
    ? new Promise((resolve) => { release = () => resolve(Response.json({ error: "down" }, { status: 503 })); })
    : path === "/api/session" ? session() : Response.json({ error: "unauthorized" }, { status: 401 }));
  client.connect({ invalidate: (reason) => invalidations.push(reason), commit: (value) => commits.push(value) }); client.state = "authenticated"; client.csrf = "c".repeat(32);
  const logout = client.logout(); assert.equal(client.state, "anonymous"); assert.deepEqual(invalidations, ["logout"]);
  release(); await assert.rejects(logout, /service_unavailable/); assert.equal(client.state, "anonymous");
  await assert.rejects(client.getResult(id), /unauthorized|AbortError/);
  client.fetcher = async () => Response.json({ authenticated: false }); client.state = "authenticated"; client.csrf = "c".repeat(32); await client.logout(); assert.equal(client.state, "anonymous"); assert.equal(commits.length, 0); assert.ok(invalidations.length >= 2);
}); test("abort settles ignored work and a newer operation defeats reversed completion", async () => {
  let sessions = 0; const commits = []; const client = new SessionClient(async (path) => {
    if (path === "/api/session" && sessions++ === 0) return new Promise(() => {}); if (path === "/api/session") return session();
    return Response.json({ status: "ok", result: result("b".repeat(32)) }); });
  client.connect({ commit: (value) => commits.push(value) }); const older = client.getResult(id);
  await new Promise((resolve) => setImmediate(resolve));
  const newer = client.getResult("b".repeat(32)); await assert.rejects(older, { name: "AbortError" }); await newer;
  assert.equal(commits.length, 1); assert.equal(commits[0][0].scanId, "b".repeat(32));
}); test("a pending response body settles on abort", async () => {
  const hanging = new Response(new ReadableStream({ pull() {} }), { headers: { "content-type": "application/json" } });
  const client = new SessionClient(async () => hanging); const controller = new AbortController(); const pending = client.getResult(id, { signal: controller.signal });
  await new Promise((resolve) => setImmediate(resolve)); controller.abort(); await assert.rejects(pending, { name: "AbortError" });
}); test("renderer keeps every normalized field inert", async () => {
  const texts = []; class Element { constructor() { this.childNodes = []; this.dataset = {}; } append(...nodes) { this.childNodes.push(...nodes); } querySelectorAll() { return []; }
    set textContent(value) { texts.push(String(value)); } set innerHTML(_value) { assert.fail("active rendering"); } }
  const prior = globalThis.document; globalThis.document = { createElement: () => new Element() }; try { const { renderResults } = await import("../public/results.js"); const container = new Element();
    renderResults(container, [{ scanId: id, target: "<img src=x onerror=alert(1)>", risk: "unknown", state: "unknown", confidence: "low",
      evidence: [], providers: [], limitations: ["fixed"] }]); assert.ok(texts.includes("<img src=x onerror=alert(1)>")); }
  finally { if (prior === undefined) delete globalThis.document; else globalThis.document = prior; } });
