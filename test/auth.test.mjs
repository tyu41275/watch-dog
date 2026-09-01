import assert from "node:assert/strict";
import test from "node:test";

import {
  SESSION_COOKIE,
  SESSION_TTL_SECONDS,
  createSession,
  expireSessionCookie,
  readAuthSecrets,
  sameOriginMutation,
  throttleFingerprint,
  verifyCredentials,
  verifySession,
} from "../dist/worker/auth.js";

const env = {
  ADMIN_USERNAME: "judge",
  ADMIN_PASSWORD: "correct horse battery staple",
  SESSION_SIGNING_KEY: "a".repeat(32),
};

test("static credentials have no defaults and compare through the signed boundary", async () => {
  assert.equal(readAuthSecrets({}), null);
  assert.equal(readAuthSecrets({ ...env, ADMIN_USERNAME: "" }), null);
  assert.equal(readAuthSecrets({ ...env, ADMIN_PASSWORD: "" }), null);
  assert.equal(readAuthSecrets({ ...env, SESSION_SIGNING_KEY: "short" }), null);

  const secrets = readAuthSecrets(env);
  assert.ok(secrets);
  assert.equal(await verifyCredentials("judge", env.ADMIN_PASSWORD, secrets), true);
  assert.equal(await verifyCredentials("judge", "wrong", secrets), false);
  assert.equal(await verifyCredentials("admin", "admin", secrets), false);
});

test("session cookie is opaque, signed, secure, expiring, and key-rotation bound", async () => {
  const secrets = readAuthSecrets(env);
  assert.ok(secrets);
  const now = Date.UTC(2026, 8, 1, 1, 0, 0);
  const session = await createSession(secrets, now);

  assert.match(session.cookie, new RegExp(`^${SESSION_COOKIE}=[A-Za-z0-9_.-]+`));
  assert.match(session.cookie, /; Path=\//);
  assert.match(session.cookie, /; HttpOnly/);
  assert.match(session.cookie, /; Secure/);
  assert.match(session.cookie, /; SameSite=Strict/);
  assert.match(session.cookie, new RegExp(`; Max-Age=${SESSION_TTL_SECONDS}$`));
  assert.doesNotMatch(session.cookie, /judge|correct|password/i);

  const accepted = await verifySession(session.cookie, secrets, now);
  assert.deepEqual(accepted, session.claims);
  const last = session.token.at(-1);
  const tampered = `${session.token.slice(0, -1)}${last === "A" ? "B" : "A"}`;
  assert.equal(await verifySession(`${SESSION_COOKIE}=${tampered}`, secrets, now), null);
  assert.equal(await verifySession(session.cookie, secrets, now + SESSION_TTL_SECONDS * 1_000), null);

  const rotated = readAuthSecrets({ ...env, SESSION_SIGNING_KEY: "b".repeat(32) });
  assert.ok(rotated);
  assert.equal(await verifySession(session.cookie, rotated, now), null);
  assert.equal(
    expireSessionCookie(),
    `${SESSION_COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`,
  );
});

test("mutations require exact same origin and throttle keys do not retain raw input", async () => {
  const matching = new Request("https://watch.example/api/logout", {
    method: "POST",
    headers: { origin: "https://watch.example" },
  });
  assert.equal(sameOriginMutation(matching), true);
  assert.equal(sameOriginMutation(new Request(matching, { headers: {} })), false);
  assert.equal(sameOriginMutation(new Request(matching, {
    headers: { origin: "https://attacker.example" },
  })), false);

  const fingerprint = await throttleFingerprint("192.0.2.9", "judge", env.SESSION_SIGNING_KEY);
  assert.match(fingerprint, /^[A-Za-z0-9_-]{43}$/);
  assert.doesNotMatch(fingerprint, /judge|192/);
  assert.equal(
    fingerprint,
    await throttleFingerprint("192.0.2.9", "judge", env.SESSION_SIGNING_KEY),
  );
  assert.notEqual(
    fingerprint,
    await throttleFingerprint("192.0.2.9", "judge", "b".repeat(32)),
  );
});
