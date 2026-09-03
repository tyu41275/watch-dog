import assert from "node:assert/strict";
import test from "node:test";

import {
  CSRF_HEADER,
  createSession,
  readAuthSecrets,
  verifySession,
} from "../dist/worker/auth.js";
import { SessionCoordinator } from "../dist/worker/coordinator.js";
import worker from "../dist/worker/index.js";

class MemoryStorage {
  values = new Map();
  async get(key) { return structuredClone(this.values.get(key)); }
  async put(key, value) { this.values.set(key, structuredClone(value)); }
  async delete(key) { return this.values.delete(key); }
}

function configured() {
  const coordinator = new SessionCoordinator({ storage: new MemoryStorage() });
  const env = {
    ADMIN_USERNAME: "judge",
    ADMIN_PASSWORD: "correct horse battery staple",
    SESSION_SIGNING_KEY: "s".repeat(32),
    SESSION_COORDINATOR: {
      idFromName: (name) => name,
      get: () => coordinator,
    },
  };
  return { coordinator, env };
}

function loginRequest(credentials, ip = "192.0.2.20") {
  return new Request("https://watch.example/api/login", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "cf-connecting-ip": ip,
      origin: "https://watch.example",
    },
    body: JSON.stringify(credentials),
  });
}

test("the exported Worker entrypoint serves health without secrets", async () => {
  const response = await worker.fetch(new Request("https://example.test/api/health"), {});
  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), { status: "ok", service: "watch-dog" });
});

test("revision is exact and fails closed when its binding is absent or malformed", async () => {
  const request = new Request("https://example.test/api/revision");
  for (const BUILD_REVISION of [undefined, "ABC", "a".repeat(39), "g".repeat(40)]) {
    const response = await worker.fetch(request.clone(), { BUILD_REVISION });
    assert.equal(response.status, 503);
    assert.deepEqual(await response.json(), { error: "revision_unavailable" });
  }
  const revision = "1".repeat(40);
  const response = await worker.fetch(request, { BUILD_REVISION: revision });
  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), { revision });
});

test("the real entrypoint fails closed for unimplemented API routes", async () => {
  const response = await worker.fetch(new Request("https://example.test/api/scans", { method: "POST" }), {});
  assert.equal(response.status, 503);
  assert.deepEqual(await response.json(), { error: "not_configured" });
});

test("the real entrypoint delegates public requests to the asset binding", async () => {
  const response = await worker.fetch(new Request("https://example.test/"), {
    ASSETS: { fetch: async () => new Response("asset") },
  });
  assert.equal(await response.text(), "asset");
});

test("actual Worker login creates a signed cookie and enforces session plus CSRF", async () => {
  const { env } = configured();
  const response = await worker.fetch(loginRequest({
    username: env.ADMIN_USERNAME,
    password: env.ADMIN_PASSWORD,
  }), env);
  assert.equal(response.status, 200);
  const body = await response.json();
  assert.equal(body.authenticated, true);
  assert.match(body.csrf_token, /^[A-Za-z0-9_-]{32}$/);
  const cookie = response.headers.get("set-cookie");
  assert.match(cookie, /HttpOnly; Secure; SameSite=Strict/);

  const status = await worker.fetch(new Request("https://watch.example/api/session", {
    headers: { cookie },
  }), env);
  assert.equal(status.status, 200);
  assert.equal((await status.json()).authenticated, true);

  const wrongCsrf = await worker.fetch(new Request("https://watch.example/api/logout", {
    method: "POST",
    headers: {
      cookie,
      origin: "https://watch.example",
      [CSRF_HEADER]: "wrong",
    },
  }), env);
  assert.equal(wrongCsrf.status, 401);
  assert.deepEqual(await wrongCsrf.json(), { error: "unauthorized" });

  const logout = await worker.fetch(new Request("https://watch.example/api/logout", {
    method: "POST",
    headers: {
      cookie,
      origin: "https://watch.example",
      [CSRF_HEADER]: body.csrf_token,
    },
  }), env);
  assert.equal(logout.status, 200);
  assert.match(logout.headers.get("set-cookie"), /Max-Age=0/);
});

test("authenticated paste HTML stores results while origin and CSRF stay mandatory", async () => {
  const { env } = configured();
  const login = await worker.fetch(loginRequest({
    username: env.ADMIN_USERNAME, password: env.ADMIN_PASSWORD,
  }), env);
  const { csrf_token: csrf } = await login.json();
  const cookie = login.headers.get("set-cookie");
  const body = JSON.stringify({
    mode: "html",
    base_url: "https://source.example/dir/page",
    html: '<script>throw 1</script><img src="https://never.invalid/x"><a href="../target">target</a>',
  });
  const headers = {
    cookie, origin: "https://watch.example", "content-type": "application/json", [CSRF_HEADER]: csrf,
  };
  const scan = await worker.fetch(new Request("https://watch.example/api/scans/paste", {
    method: "POST", headers, body,
  }), env);
  assert.equal(scan.status, 201);
  const receipt = await scan.json();
  assert.equal(receipt.mode, "paste_html");
  assert.equal(receipt.accepted_targets, 1);
  assert.equal(receipt.scan_ids.length, 1);
  assert.match(receipt.receipt_id, /^[a-f0-9]{32}$/);
  assert.notEqual(receipt.receipt_id, receipt.scan_ids[0]);

  const stored = await worker.fetch(new Request(
    `https://watch.example/api/results/${receipt.scan_ids[0]}`,
    { headers: { cookie } },
  ), env);
  assert.equal(stored.status, 200);
  assert.equal((await stored.json()).result.canonical_target, "https://source.example/target");

  for (const rejectedHeaders of [
    { ...headers, origin: "https://attacker.example" },
    { ...headers, [CSRF_HEADER]: "wrong" },
  ]) {
    const denied = await worker.fetch(new Request("https://watch.example/api/scans/paste", {
      method: "POST", headers: rejectedHeaders, body,
    }), env);
    assert.equal(denied.status, 401);
  }
});

test("actual Worker gates and composes the live provider for both scan routes", async () => {
  const secret = "route-only-provider-key";
  const { env } = configured();
  env.GOOGLE_SAFE_BROWSING_API_KEY = secret;
  const originalFetch = globalThis.fetch;
  const providerCalls = [];
  globalThis.fetch = async (input, init) => {
    providerCalls.push({ url: new URL(input), headers: new Headers(init.headers) });
    return Response.json({ cacheDuration: "1s" });
  };
  try {
    const login = await worker.fetch(loginRequest({
      username: env.ADMIN_USERNAME, password: env.ADMIN_PASSWORD,
    }), env);
    const { csrf_token: csrf } = await login.json();
    const cookie = login.headers.get("set-cookie");
    const headers = {
      cookie, origin: "https://watch.example", "content-type": "application/json", [CSRF_HEADER]: csrf,
    };
    const submit = async (path, body) => {
      const response = await worker.fetch(new Request(`https://watch.example${path}`, {
        method: "POST", headers, body: JSON.stringify(body),
      }), env);
      assert.equal(response.status, 201);
      const receipt = await response.json();
      const stored = await worker.fetch(new Request(
        `https://watch.example/api/results/${receipt.scan_ids[0]}`,
        { headers: { cookie } },
      ), env);
      assert.equal(stored.status, 200);
      return (await stored.json()).result;
    };

    const disabled = await submit("/api/scans/paste", {
      mode: "html", base_url: "https://paste.example/", html: '<a href="/disabled">x</a>',
    });
    assert.equal(disabled.provider_observations[0].state, "not_configured");
    assert.equal(providerCalls.length, 0);

    env.GOOGLE_SAFE_BROWSING_ENABLED = "true";
    const paste = await submit("/api/scans/paste", {
      mode: "html", base_url: "https://paste.example/", html: '<a href="/enabled">x</a>',
    });
    const observedAt = new Date().toISOString();
    const live = await submit("/api/scans/live", {
      document_url: "https://watch.example/reference",
      observed_at: observedAt,
      candidates: [{
        raw_href: "https://live.example/enabled",
        anchor_text: "live",
        base_url: "https://watch.example/reference",
        provenance: {
          source: "live_page",
          document_url: "https://watch.example/reference",
          occurrence_index: 0,
          extracted_at: observedAt,
        },
      }],
      extraction_rejections: [],
    });
    assert.equal(paste.provider_observations[0].source, "live");
    assert.equal(live.provider_observations[0].source, "live");
    assert.equal(JSON.stringify([paste, live]).includes(secret), false);
    assert.equal(providerCalls.length, 2);
    for (const call of providerCalls) {
      assert.equal(call.url.origin + call.url.pathname,
        "https://safebrowsing.googleapis.com/v5/urls:search");
      assert.equal(call.url.searchParams.size, 2);
      assert.equal(call.url.searchParams.get("alt"), "proto");
      assert.equal(call.headers.get("x-goog-api-key"), secret);
      assert.equal(call.url.href.includes(secret), false);
    }
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("wrong, missing, and default credentials deny generically and throttle", async () => {
  const missing = await worker.fetch(loginRequest({ username: "admin", password: "admin" }), {});
  assert.equal(missing.status, 401);
  assert.deepEqual(await missing.json(), { error: "invalid_credentials" });

  const { env } = configured();
  for (let attempt = 0; attempt < 5; attempt += 1) {
    const denied = await worker.fetch(loginRequest({
      username: env.ADMIN_USERNAME,
      password: "wrong",
    }), env);
    assert.equal(denied.status, 401);
    assert.deepEqual(await denied.json(), { error: "invalid_credentials" });
  }
  const throttled = await worker.fetch(loginRequest({
    username: env.ADMIN_USERNAME,
    password: "wrong",
  }), env);
  assert.equal(throttled.status, 429);
  assert.deepEqual(await throttled.json(), { error: "invalid_credentials" });
  assert.match(throttled.headers.get("retry-after"), /^\d+$/);
});

test("login bounds its stream and denies coordinator failures before cookie issuance", async () => {
  let pulls = 0;
  let cancelled = false;
  const body = new ReadableStream({
    pull(controller) { pulls += 1; controller.enqueue(new Uint8Array(1_024)); },
    cancel() { cancelled = true; },
  });
  const { env } = configured();
  const oversized = await worker.fetch(new Request("https://watch.example/api/login", {
    method: "POST", body, duplex: "half", headers: { origin: "https://watch.example" },
  }), env);
  assert.equal(oversized.status, 401);
  assert.equal(cancelled, true);
  assert.ok(pulls <= 6);

  const attemptFailure = { ...env, SESSION_COORDINATOR: {
    idFromName: () => "global", get: () => ({ fetch: async () => { throw new Error("offline"); } }),
  } };
  const resolutionFailures = [
    { idFromName() { throw new Error("id unavailable"); }, get() { throw new Error("unused"); } },
    { idFromName: () => "global", get() { throw new Error("stub unavailable"); } },
  ].map((SESSION_COORDINATOR) => ({ ...env, SESSION_COORDINATOR }));
  const resetFailure = { ...env, SESSION_COORDINATOR: {
    idFromName: () => "global", get: () => ({ fetch: async (request) =>
      new URL(request.url).pathname.endsWith("attempt")
        ? Response.json({ allowed: true, retry_after_seconds: 0 })
        : new Response(null, { status: 503 }) }),
  } };
  for (const failed of [attemptFailure, resetFailure, ...resolutionFailures]) {
    const response = await worker.fetch(loginRequest({
      username: env.ADMIN_USERNAME, password: env.ADMIN_PASSWORD,
    }), failed);
    assert.equal(response.status, 401);
    assert.deepEqual(await response.json(), { error: "invalid_credentials" });
    assert.equal(response.headers.get("set-cookie"), null);
  }
});

test("session route rejects missing, tampered, expired, and rotated cookies", async () => {
  const { env } = configured();
  const secrets = readAuthSecrets(env);
  const current = await createSession(secrets);
  const expired = await createSession(secrets, Date.now() - 20 * 60 * 1_000);
  const rotated = await createSession(readAuthSecrets({
    ...env, SESSION_SIGNING_KEY: "r".repeat(32),
  }));
  const cookies = [null, `${current.cookie.split(";")[0]}x`, expired.cookie, rotated.cookie];
  for (const cookie of cookies) {
    const response = await worker.fetch(new Request("https://watch.example/api/session", {
      headers: cookie === null ? {} : { cookie },
    }), env);
    assert.equal(response.status, 401);
    assert.deepEqual(await response.json(), { error: "unauthorized" });
  }
  const wrongOrigin = await worker.fetch(new Request(loginRequest({
    username: env.ADMIN_USERNAME, password: env.ADMIN_PASSWORD,
  }), { headers: { origin: "https://attacker.example" } }), env);
  assert.equal(wrongOrigin.status, 401);
});

test("explicit Live results are opaque, session-owned, and unavailable cross-session", async () => {
  const { coordinator, env } = configured();
  const firstLogin = await worker.fetch(loginRequest({
    username: env.ADMIN_USERNAME,
    password: env.ADMIN_PASSWORD,
  }, "192.0.2.21"), env);
  const firstCookie = firstLogin.headers.get("set-cookie");
  const secrets = readAuthSecrets(env);
  const firstClaims = await verifySession(firstCookie, secrets);

  const result = {
    scan_id: "pending",
    mode: "live_page",
    canonical_target: "https://example.test/",
    risk_label: "unknown",
    analysis_state: "unknown",
    confidence: "low",
    supporting_evidence: [],
    contradicting_evidence: [],
    provider_observations: [],
    limitations: ["No provider observation was available."],
  };
  const seeded = await coordinator.fetch(new Request("https://coordinator/live-results", {
    method: "POST",
    body: JSON.stringify({ version: 1, session_id: firstClaims.sid, result }),
  }));
  const { scan_id } = await seeded.json();
  assert.match(scan_id, /^[a-f0-9]{32}$/);

  const owned = await worker.fetch(new Request(`https://watch.example/api/results/${scan_id}`, {
    headers: { cookie: firstCookie },
  }), env);
  assert.equal(owned.status, 200);
  assert.equal((await owned.json()).status, "ok");

  const secondLogin = await worker.fetch(loginRequest({
    username: env.ADMIN_USERNAME,
    password: env.ADMIN_PASSWORD,
  }, "192.0.2.22"), env);
  const crossSession = await worker.fetch(
    new Request(`https://watch.example/api/results/${scan_id}`, {
      headers: { cookie: secondLogin.headers.get("set-cookie") },
    }),
    env,
  );
  assert.equal(crossSession.status, 403);
  assert.deepEqual(await crossSession.json(), { error: "unauthorized" });

  const legacy = await coordinator.fetch(new Request("https://coordinator/results", {
    method: "POST", body: JSON.stringify({ session_id: firstClaims.sid, result }),
  }));
  assert.equal(legacy.status, 404);
});
