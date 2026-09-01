import assert from "node:assert/strict";
import test from "node:test";

import {
  CoordinatorCore,
  RESULT_TTL_SECONDS,
  SessionCoordinator,
  THROTTLE_ATTEMPTS,
  THROTTLE_BLOCK_MS,
  THROTTLE_WINDOW_MS,
} from "../dist/worker/coordinator.js";

const result = {
  scan_id: "internal_pending",
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

class MemoryStorage {
  values = new Map();

  async get(key) {
    return structuredClone(this.values.get(key));
  }

  async put(key, value) {
    this.values.set(key, structuredClone(value));
  }

  async delete(key) {
    return this.values.delete(key);
  }
}

test("coordinator core throttles, blocks, resets, and starts a new bounded window", () => {
  const core = new CoordinatorCore();
  const key = "k";
  const now = 1_000_000;
  for (let attempt = 0; attempt < THROTTLE_ATTEMPTS; attempt += 1) {
    assert.deepEqual(core.attemptLogin(key, now + attempt), {
      allowed: true,
      retry_after_seconds: 0,
    });
  }
  const blocked = core.attemptLogin(key, now + THROTTLE_ATTEMPTS);
  assert.equal(blocked.allowed, false);
  assert.equal(blocked.retry_after_seconds, THROTTLE_BLOCK_MS / 1_000);
  assert.equal(core.attemptLogin(key, now + THROTTLE_ATTEMPTS + 1).allowed, false);

  core.resetLogin(key);
  assert.equal(core.attemptLogin(key, now).allowed, true);
  assert.equal(core.attemptLogin("new-window", now).allowed, true);
  assert.equal(core.attemptLogin("new-window", now + THROTTLE_WINDOW_MS).allowed, true);
});

test("opaque results are cloned, session-owned, expiring, and never durable", () => {
  const core = new CoordinatorCore();
  const now = 2_000_000;
  const scanId = core.putResult("a".repeat(32), result, now);
  assert.match(scanId, /^[a-f0-9]{32}$/);
  assert.deepEqual(core.getResult("b".repeat(32), scanId, now), { status: "unauthorized" });

  const owned = core.getResult("a".repeat(32), scanId, now);
  assert.equal(owned.status, "ok");
  assert.equal(owned.result.scan_id, scanId);
  owned.result.limitations.push("caller mutation");
  assert.equal(core.getResult("a".repeat(32), scanId, now).result.limitations.length, 1);
  assert.deepEqual(
    core.getResult("a".repeat(32), scanId, now + RESULT_TTL_SECONDS * 1_000),
    { status: "expired" },
  );
  assert.deepEqual(core.getResult("a".repeat(32), scanId, now), { status: "missing" });
});

test("actual coordination object persists only hashed throttle records", async () => {
  const storage = new MemoryStorage();
  const state = { storage };
  const key = "x".repeat(43);
  await assert.rejects(
    new SessionCoordinator().fetch(new Request("https://coordinator/throttle/attempt", {
      method: "POST", body: JSON.stringify({ key }),
    })),
    /storage/,
  );
  for (let attempt = 0; attempt <= THROTTLE_ATTEMPTS; attempt += 1) {
    const object = new SessionCoordinator(state);
    const response = await object.fetch(new Request("https://coordinator/throttle/attempt", {
      method: "POST",
      body: JSON.stringify({ key }),
    }));
    const decision = await response.json();
    assert.equal(decision.allowed, attempt < THROTTLE_ATTEMPTS);
  }
  assert.deepEqual([...storage.values.keys()], [`throttle:${key}`]);
  assert.doesNotMatch(JSON.stringify([...storage.values]), /username|password|html|result/i);

  const reset = await new SessionCoordinator(state).fetch(new Request("https://coordinator/throttle/reset", {
    method: "POST", body: JSON.stringify({ key }),
  }));
  assert.equal(reset.status, 200);
  assert.equal(storage.values.size, 0);
  storage.values.set(`throttle:${key}`, {
    started_at: Date.now() - THROTTLE_WINDOW_MS, attempts: THROTTLE_ATTEMPTS, blocked_until: 0,
  });
  const nextWindow = await new SessionCoordinator(state).fetch(new Request("https://coordinator/throttle/attempt", {
    method: "POST", body: JSON.stringify({ key }),
  }));
  assert.equal((await nextWindow.json()).allowed, true);

  const object = new SessionCoordinator(state);
  const stored = await object.fetch(new Request("https://coordinator/results", {
    method: "POST",
    body: JSON.stringify({ session_id: "s".repeat(32), result }),
  }));
  assert.equal(stored.status, 201);
  const { scan_id } = await stored.json();
  const unauthorized = await object.fetch(new Request(`https://coordinator/results/${scan_id}`, {
    headers: { "x-watchdog-session": "t".repeat(32) },
  }));
  assert.equal(unauthorized.status, 403);
  assert.equal(storage.values.size, 1, "result must remain outside durable storage");
});
