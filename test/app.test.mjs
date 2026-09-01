import assert from "node:assert/strict"; import test from "node:test"; import { SessionClient } from "../public/session-client.js";
const id = "a".repeat(32), token = "c".repeat(32); const session = () => Response.json({ authenticated: true, csrf_token: token, expires_at: "2026-09-01T13:00:00.000Z" });
const result = (scanId = id, overrides = {}) => ({ kind: "analyzed", scan_id: scanId, mode: "paste_html", canonical_target: "https://example.com/", unscannable_reason: null,
  outcome: "unknown", risk_label: "unknown", analysis_state: "unknown", confidence: "low", supporting_evidence: [], contradicting_evidence: [], provider_observations: [],
  limitation_codes: ["no_provider_observation", "confidence_basis"], ...overrides });
const receipt = (overrides = {}) => Response.json({ mode: "paste_html", scan_ids: [id], accepted_targets: 1, rejected_candidates: 0, truncated: false, unscannable_reason: null, ...overrides }, { status: 201 });
const scan = (client) => client.scanPaste({ mode: "html", html: "<a>x</a>", base_url: "https://example.com/" }, { consent: true });
test("one controller owns consent, decoding, final reauth, and commit", async () => {
  const calls = [], commits = []; const client = new SessionClient(async (path, init) => { calls.push({ path, init }); return path === "/api/session" ? session() :
    path === "/api/scans/paste" ? receipt() : Response.json({ status: "ok", result: result() }); }); client.connect({ commit: (value) => commits.push(value) });
  await assert.rejects(client.scanPaste({ mode: "html" }, { consent: false }), /provider_consent_required/); assert.equal(calls.length, 0); assert.equal((await scan(client)).results[0].risk, "unknown");
  assert.deepEqual(calls.map(({ path }) => path), ["/api/session", "/api/scans/paste", `/api/results/${id}`, "/api/session"]); assert.equal(commits.length, 1); assert.equal(calls[1].init.headers["x-watchdog-provider-consent"], "google_safe_browsing");
}); test("every auth phase invalidates before malformed or pending 401/403 bodies", async () => {
  for (const phase of ["session", "scan", "result", "final"]) for (const status of [401, 403]) for (const pending of [false, true]) {
    let sessions = 0, parsed = false; const denied = new Response("not-json", { status }); if (pending) denied.json = () => { parsed = true; return new Promise(() => {}); };
    const client = new SessionClient(async (path) => path === "/api/session" ? (phase === "session" && sessions++ === 0 || phase === "final" && sessions++ === 1 ? denied : session()) :
      path === "/api/scans/paste" && phase === "scan" ? denied : path.startsWith("/api/results/") && phase === "result" ? denied :
        path === "/api/scans/paste" ? receipt() : Response.json({ status: "ok", result: result() })); client.state = "authenticated"; client.csrf = token;
    await assert.rejects(scan(client), /unauthorized/); assert.equal(client.state, "anonymous", `${phase}/${status}`); assert.equal(client.csrf, null); assert.equal(parsed, false); }
}); test("logout excludes operations and remains anonymous after success or failure", async () => {
  for (const succeeds of [true, false]) { let release, calls = 0; const commits = []; const client = new SessionClient(async () => { calls += 1;
    return new Promise((resolve) => { release = () => resolve(succeeds ? Response.json({ authenticated: false }) : Response.json({ error: "down" }, { status: 503 })); }); });
    client.connect({ commit: (value) => commits.push(value) }); client.state = "authenticated"; client.csrf = token; const logout = client.logout(); assert.equal(client.state, "anonymous");
    await assert.rejects(client.getResult(id), /unauthorized/); await assert.rejects(scan(client), /unauthorized/); assert.equal(calls, 1); release();
    if (succeeds) await logout; else await assert.rejects(logout, /service_unavailable/); assert.equal(client.state, "anonymous"); assert.equal(client.csrf, null); assert.equal(commits.length, 0); }
}); test("receipt/result contradictions cannot commit", async () => { const commits = []; const client = new SessionClient(async (path) => path === "/api/session" ? session() : path === "/api/scans/paste" ?
  receipt({ accepted_targets: 0, rejected_candidates: 1, unscannable_reason: "invalid_url" }) : Response.json({ status: "ok", result: result() }));
  client.connect({ commit: (value) => commits.push(value) }); await assert.rejects(scan(client), /malformed_response/); assert.equal(commits.length, 0); });
test("abort settles ignored fetch/body work and newer completion is sole", async () => { let sessions = 0; const commits = []; const client = new SessionClient(async (path) => {
  if (path === "/api/session" && sessions++ === 0) return new Promise(() => {}); if (path === "/api/session") return session(); return Response.json({ status: "ok", result: result("b".repeat(32)) }); });
  client.connect({ commit: (value) => commits.push(value) }); const older = client.getResult(id); await new Promise((resolve) => setImmediate(resolve)); const newer = client.getResult("b".repeat(32));
  await assert.rejects(older, { name: "AbortError" }); await newer; assert.equal(commits.length, 1); const hanging = new Response(new ReadableStream({ pull() {} }), { headers: { "content-type": "application/json" } });
  client.fetcher = async () => hanging; const controller = new AbortController(), body = client.getResult(id, { signal: controller.signal }); await new Promise((resolve) => setImmediate(resolve));
  controller.abort(); await assert.rejects(body, { name: "AbortError" }); });
test("renderer keeps normalized fields inert", async () => { const texts = []; class Element { constructor() { this.childNodes = []; this.dataset = {}; } append(...nodes) { this.childNodes.push(...nodes); }
  querySelectorAll() { return []; } set textContent(value) { texts.push(String(value)); } set innerHTML(_value) { assert.fail("active rendering"); } } const prior = globalThis.document;
  globalThis.document = { createElement: () => new Element() }; try { const { renderResults } = await import("../public/results.js"); renderResults(new Element(), [{ scanId: id, target: "<img src=x onerror=alert(1)>",
    risk: "unknown", state: "unknown", confidence: "low", evidence: [], providers: [], limitations: ["fixed"] }]);
    assert.ok(texts.includes("<img src=x onerror=alert(1)>")); } finally { if (prior === undefined) delete globalThis.document; else globalThis.document = prior; } });
