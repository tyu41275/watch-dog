import assert from "node:assert/strict";
import test from "node:test";

import {
  CSRF_HEADER,
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

test("results are opaque, session-owned, and unavailable cross-session", async () => {
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
    mode: "paste_url",
    canonical_target: "https://example.test/",
    risk_label: "unknown",
    analysis_state: "unknown",
    confidence: "low",
    supporting_evidence: [],
    contradicting_evidence: [],
    provider_observations: [],
    limitations: ["No provider observation was available."],
  };
  const seeded = await coordinator.fetch(new Request("https://coordinator/results", {
    method: "POST",
    body: JSON.stringify({ session_id: firstClaims.sid, result }),
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
});
