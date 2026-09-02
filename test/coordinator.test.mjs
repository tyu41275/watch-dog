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
import { executePasteScan } from "../dist/worker/fetch/paste.js";

const result = {
  scan_id: "internal_pending",
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
const hex = (value) => value.toString(16).padStart(32, "0");

async function withUuid(factory, work) {
  const descriptor = Object.getOwnPropertyDescriptor(crypto, "randomUUID"); let calls = 0;
  try {
    Object.defineProperty(crypto, "randomUUID", { configurable: true, value: () => factory(calls++) });
    return await work(() => calls);
  } finally { descriptor === undefined ? delete crypto.randomUUID : Object.defineProperty(crypto, "randomUUID", descriptor); }
}

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

test("Live-only results are cloned, session-owned, expiring, and mode checked", () => {
  const core = new CoordinatorCore();
  const now = 2_000_000;
  const scanId = core.putLiveResult("a".repeat(32), result, now);
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
  assert.throws(() => core.putLiveResult("a".repeat(32), { ...result, mode: "paste_url" }, now));
});

test("Paste replay allocates one bound vector and commits one session snapshot", async () => {
  const core = new CoordinatorCore();
  const session = "s".repeat(32);
  const now = 3_000_000;
  const operation = await executePasteScan({ mode: "html", base_url: "https://source.example/",
    html: '<a href="/one">one</a><a href="/two">two</a>' },
  { now: () => new Date("2026-09-01T03:00:00Z") });
  assert.deepEqual(Object.keys(operation).sort(), ["input", "journal", "version"]);
  assert.equal(operation.journal.at(-1).effect.kind, "OBSERVE_PROVIDER");
  const receipt = core.commitPaste(session, operation.input, operation.journal, now);
  assert.match(receipt.receipt_id, /^[a-f0-9]{32}$/);
  assert.equal(receipt.scan_ids.length, 2);
  assert.equal(new Set([receipt.receipt_id, ...receipt.scan_ids]).size, 3);
  assert.deepEqual(core.getReceipt(session, receipt.receipt_id, now).receipt, receipt);
  for (const id of receipt.scan_ids) {
    assert.equal(core.getResult(session, id, now).result.scan_id, id);
    assert.deepEqual(core.getResult("x".repeat(32), id, now), { status: "unauthorized" });
  }
  assert.throws(() => core.commitPaste(session, operation.input, operation.journal.slice(0, -1), now));
  assert.deepEqual(core.getReceipt(session, receipt.receipt_id, now).receipt, receipt);
  assert.deepEqual(core.getReceipt(session, receipt.receipt_id,
    now + RESULT_TTL_SECONDS * 1_000), { status: "expired" });
});

test("logical liveness is independent of scale, order, session, kind, and vector position", async () => {
  const now = 4_000_000;
  const operation = await executePasteScan({ mode: "html", base_url: "https://source.example/",
    html: Array.from({ length: 16 }, (_, index) => `<a href="/${index}">${index}</a>`).join("") });
  for (const size of [0, 1, 63, 64, 65, 128, 257]) for (let position = 0; position < 17; position += 1) {
    for (const offset of size === 0 ? [0] : [1, 0, -1]) {
      const core = new CoordinatorCore();
      const ids = Array.from({ length: 17 }, (_, index) => hex(1_000 + index));
      const records = new Map(Array.from({ length: Math.max(0, size - 1) }, (_, index) =>
        [hex(10_000 + index), { kind: "result", session_id: index % 2 ? "x" : "y",
          expires_at: now + (index % 3) - 1, result }]));
      if (size > 0) records.set(ids[position], position % 2
        ? { kind: "result", session_id: "other", expires_at: now + offset, result }
        : { kind: "receipt", session_id: "other", expires_at: now + offset, exchange: {} });
      core.snapshot = { records };
      const old = core.snapshot, order = [...records.keys()];
      await withUuid((call) => ids[call], (calls) => {
        if (size > 0 && offset === 1) {
          assert.throws(() => core.commitPaste("s".repeat(32), operation.input, operation.journal, now), /collision/);
          assert.equal(core.snapshot, old); assert.deepEqual([...records.keys()], order); assert.equal(calls(), 17);
        } else {
          const receipt = core.commitPaste("s".repeat(32), operation.input, operation.journal, now);
          assert.equal(receipt.receipt_id, ids[0]); assert.notEqual(core.snapshot, old); assert.equal(calls(), 17);
        }
      });
    }
  }
});

test("tampered prefixes and allocation or preparation faults preserve the old snapshot", async () => {
  const core = new CoordinatorCore();
  const session = "s".repeat(32);
  const operation = await executePasteScan({ mode: "html", base_url: "https://source.example/",
    html: '<a href="/one">one</a><a href="/two">two</a>' });
  const first = core.commitPaste(session, operation.input, operation.journal, 0);
  const mutated = structuredClone(operation.journal);
  mutated[0].effect.id += 1;
  for (const journal of [operation.journal.slice(0, -1), [...operation.journal, operation.journal[0]],
    [operation.journal[1], operation.journal[0], ...operation.journal.slice(2)], mutated]) {
    assert.throws(() => core.commitPaste(session, operation.input, journal, 0));
  }
  assert.deepEqual(core.getReceipt(session, first.receipt_id, 0).receipt, first);

  await withUuid(() => first.receipt_id, () => {
    assert.throws(() => core.commitPaste(session, operation.input, operation.journal, 0), /collision/);
  });
  const clone = globalThis.structuredClone;
  try {
    globalThis.structuredClone = () => { throw new Error("preparation failed"); };
    assert.throws(() => core.commitPaste(session, operation.input, operation.journal, 0), /preparation/);
  } finally { globalThis.structuredClone = clone; }
  assert.deepEqual(core.getReceipt(session, first.receipt_id, 0).receipt, first);
});

test("allocation faults roll back and captured reclamation batches make bounded progress", async () => {
  const operation = await executePasteScan({ mode: "html", base_url: "https://source.example/",
    html: '<a href="/one">one</a><a href="/two">two</a>' });
  for (const position of [0, 1, 2]) for (const fault of ["throw", "malformed"]) {
    const core = new CoordinatorCore(), old = core.snapshot;
    await withUuid((call) => {
      if (call === position && fault === "throw") throw new Error("generator failed");
      return call === position && fault === "malformed" ? "bad" : hex(100 + call);
    }, () => assert.throws(() => core.commitPaste("s".repeat(32), operation.input, operation.journal, 0)));
    assert.equal(core.snapshot, old);
  }
  const core = new CoordinatorCore(), now = 8_000_000;
  core.snapshot = { records: new Map(Array.from({ length: 128 }, (_, index) => [hex(20_000 + index),
    { kind: "result", session_id: "old", expires_at: now + (index < 64 ? 1 : 0), result }])) };
  await withUuid((call) => hex(30_000 + call), () => core.putLiveResult("s".repeat(32), result, now));
  assert.equal([...core.snapshot.records.keys()][0], hex(20_064));
  await withUuid((call) => hex(31_000 + call), () => core.putLiveResult("s".repeat(32), result, now));
  assert.equal(core.snapshot.records.size, 66); assert.equal(core.snapshot.records.has(hex(20_064)), false);
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
  const stored = await object.fetch(new Request("https://coordinator/live-results", {
    method: "POST",
    body: JSON.stringify({ version: 1, session_id: "s".repeat(32), result }),
  }));
  assert.equal(stored.status, 201);
  const { scan_id } = await stored.json();
  const unauthorized = await object.fetch(new Request(`https://coordinator/results/${scan_id}`, {
    headers: { "x-watchdog-session": "t".repeat(32) },
  }));
  assert.equal(unauthorized.status, 403);
  assert.equal(storage.values.size, 1, "result must remain outside durable storage");
  for (const [path, body] of [
    ["/results", { session_id: "s".repeat(32), result }],
    ["/live-results", { version: 1, session_id: "s".repeat(32), result: { ...result, mode: "paste_url" } }],
  ]) assert.notEqual((await object.fetch(new Request(`https://coordinator${path}`, {
    method: "POST", body: JSON.stringify(body),
  }))).status, 201);
});
