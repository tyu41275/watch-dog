import assert from "node:assert/strict";
import test from "node:test";
import { SessionClient } from "../public/session-client.js";

const A = "a".repeat(32);
const B = "b".repeat(32);
const CSRF = "c".repeat(32);
const session = () => Response.json({ authenticated: true, csrf_token: CSRF,
  expires_at: "2026-09-01T07:00:00.000Z" });
const scanResult = (id = A, mode = "paste_html") => ({ scan_id: id, mode,
  canonical_target: "https://example.test/", risk_label: "unknown",
  analysis_state: "unknown", confidence: "low", supporting_evidence: [],
  contradicting_evidence: [], provider_observations: [], limitations: ["bounded"] });
const envelope = (id = A, mode) => Response.json({ status: "ok",
  result: scanResult(id, mode) });
const receipt = (id = A) => Response.json({ mode: "paste_html", scan_ids: [id],
  receipt_id: "d".repeat(32), occurrence_count: { kind: "exact", count: 1 },
  accepted_targets: 1, rejected_candidates: 0, truncated: false,
  unscannable_reason: null, fetch_evidence: null, targets: [], rejections: [] },
{ status: 201 });
const paste = (client, options = {}) => client.scanPaste({ mode: "html",
  html: '<a href="/">one</a>', base_url: "https://example.test/" },
{ consent: true, ...options });
const tick = () => new Promise((resolve) => setImmediate(resolve));

test("one registry owns refresh, scan, results, final auth and commit", async () => {
  const calls = [];
  const commits = [];
  const client = new SessionClient(async (path, init) => {
    calls.push({ path, init });
    if (path === "/api/session") return session();
    if (path === "/api/scans/paste") return receipt();
    return envelope();
  });
  client.connect({ commit: (value) => commits.push(value) });
  const output = await paste(client);
  assert.equal(output.results[0].scan_id, A);
  assert.deepEqual(calls.map(({ path }) => path), [
    "/api/session", "/api/scans/paste", `/api/results/${A}`, "/api/session",
  ]);
  assert.equal(calls[1].init.headers["x-watchdog-csrf"], CSRF);
  assert.equal(commits.length, 1);
  assert.equal(client.operations.size, 0);
  assert.equal(client.auth.csrf, CSRF);
});

test("401 and 403 invalidate before any body settlement at every phase", async () => {
  for (const status of [401, 403]) for (const phase of ["initial", "scan", "result", "final"]) {
    let sessions = 0;
    let parsed = false;
    let clears = 0;
    const denied = new Response("ignored", { status });
    denied.json = () => { parsed = true; return new Promise(() => {}); };
    const client = new SessionClient(async (path) => {
      if (path === "/api/session") {
        sessions += 1;
        return phase === "initial" && sessions === 1 || phase === "final" && sessions === 2
          ? denied : session();
      }
      if (path === "/api/scans/paste") return phase === "scan" ? denied : receipt();
      return phase === "result" ? denied : envelope();
    });
    client.connect({ clear: () => { clears += 1; } });
    await assert.rejects(paste(client), /unauthorized/u, `${status}/${phase}`);
    assert.equal(parsed, false, `${status}/${phase}`);
    assert.equal(client.auth, null, `${status}/${phase}`);
    assert.equal(client.operations.size, 0, `${status}/${phase}`);
    assert.ok(clears >= 2, `${status}/${phase}`);
  }
});

test("new login wins reversed login and logout completions", async () => {
  let releaseLogin;
  let logins = 0;
  const client = new SessionClient(async (path) => {
    if (path === "/api/login" && ++logins === 1) {
      return new Promise((resolve) => { releaseLogin = resolve; });
    }
    return path === "/api/login" ? session() : Response.json({ authenticated: false });
  });
  const olderLogin = client.login({ username: "first", password: "one" });
  await tick();
  await client.login({ username: "second", password: "two" });
  await assert.rejects(olderLogin, { name: "AbortError" });
  releaseLogin(session());
  await tick();
  assert.equal(client.auth.csrf, CSRF);

  let releaseLogout;
  client.fetcher = async (path) => path === "/api/logout"
    ? new Promise((resolve) => { releaseLogout = resolve; }) : session();
  const logout = client.logout();
  assert.equal(client.auth, null);
  await tick();
  await client.login({ username: "new", password: "authority" });
  await assert.rejects(logout, { name: "AbortError" });
  releaseLogout(Response.json({ authenticated: false }));
  await tick();
  assert.equal(client.auth.csrf, CSRF);
});

test("newer result completion excludes an older final reauthentication", async () => {
  let sessions = 0;
  let releaseFinal;
  const commits = [];
  const client = new SessionClient(async (path) => {
    if (path === "/api/session") {
      sessions += 1;
      if (sessions === 2) return new Promise((resolve) => { releaseFinal = resolve; });
      return session();
    }
    if (path === "/api/scans/paste") return receipt(A);
    return path.endsWith(A) ? envelope(A) : envelope(B);
  });
  client.connect({ commit: (value) => commits.push(value) });
  const older = paste(client);
  while (releaseFinal === undefined) await tick();
  const newer = client.getResult(B);
  await assert.rejects(older, { name: "AbortError" });
  await newer;
  releaseFinal(session());
  await tick();
  assert.equal(commits.length, 1);
  assert.equal(commits[0].results[0].scan_id, B);
  assert.equal(client.operations.size, 0);
});

test("abort-ignoring fetch and JSON settle on cancel, supersession and timeout", async () => {
  const pendingFetch = new SessionClient(() => new Promise(() => {}),
    { timeoutMilliseconds: 10 });
  await assert.rejects(pendingFetch.getResult(A), { name: "AbortError" });
  assert.equal(pendingFetch.operations.size, 0);

  const controller = new AbortController();
  const pendingBody = new Response("{}");
  pendingBody.json = () => new Promise(() => {});
  const bodyClient = new SessionClient(async () => pendingBody);
  const body = bodyClient.getResult(A, { signal: controller.signal });
  await tick();
  controller.abort();
  await assert.rejects(body, { name: "AbortError" });
  assert.equal(bodyClient.operations.size, 0);

  let release;
  const superseded = new SessionClient(() => new Promise((resolve) => { release = resolve; }));
  const first = superseded.getResult(A);
  await tick();
  const second = superseded.initialize();
  await assert.rejects(first, { name: "AbortError" });
  release(session());
  assert.equal(await second, true);
  assert.equal(superseded.operations.size, 0);
});

test("consent and invalid result IDs reject before protected network entry", async () => {
  const paths = [];
  const client = new SessionClient(async (path) => { paths.push(path); return session(); });
  await assert.rejects(client.scanPaste({ mode: "url", url: "https://example.test" },
    { consent: false }), /provider_consent_required/u);
  assert.deepEqual(paths, ["/api/session"]);
  paths.length = 0;
  for (const id of [null, 7, {}, [], "short", "A".repeat(32)]) {
    await assert.rejects(client.getResult(id), /invalid_arguments/u);
  }
  assert.deepEqual(paths, []);
});
