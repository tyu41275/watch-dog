import assert from "node:assert/strict";
import test from "node:test";
import { isDeepStrictEqual } from "node:util";
import * as server from "../dist/shared/scan-machine.js";
import * as browser from "../public/protocol/scan-machine.generated.js";
import { executePasteScan } from "../dist/worker/fetch/paste.js";
import { executeLiveOperation } from "../dist/worker/live.js";
import { oneFieldMutants } from "./support/protocol-mutants.mjs";

const NOW = "2026-09-01T06:30:00.000Z";
const BASE = "https://watch.example/reference";
const ids = (count) => Array.from({ length: count }, (_, index) =>
  index.toString(16).padStart(32, "0"));
const outcome = (fn) => {
  try { return ["ok", fn()]; } catch (error) { return [error.constructor.name, error.message]; }
};
const candidate = (href, text, occurrence_index) => ({
  raw_href: href,
  anchor_text: text,
  base_url: BASE,
  provenance: {
    source: "live_page",
    document_url: BASE,
    occurrence_index,
    extracted_at: NOW,
  },
});
const provider = Object.freeze({
  provider: "google_safe_browsing",
  source: "live",
  observe: async ({ canonical_target, requested_at }) => ({
    provider: "google_safe_browsing",
    source: "live",
    queried_target: canonical_target,
    observed_at: requested_at,
    expires_at: null,
    freshness: "unknown",
    state: "not_configured",
    category: null,
    confidence: "low",
    reference: null,
    error: "not_configured",
  }),
});

function complete(api, operation) {
  let machine = api.createScanMachine(operation.input);
  const journal = [...operation.journal];
  for (const entry of operation.journal) machine = api.reduceScanMachine(machine, entry.fact);
  const fact = {
    kind: "IDS_ALLOCATED",
    effect_id: machine.pending.id,
    ids: ids(machine.pending.count),
  };
  journal.push(api.scanJournalEntry(machine.pending, fact));
  machine = api.reduceScanMachine(machine, fact);
  return { journal, exchange: machine.exchange };
}

async function liveOperation(extra = []) {
  return executeLiveOperation({
    document_url: BASE,
    observed_at: NOW,
    candidates: [
      candidate("/same#one", "First", 0),
      candidate("/same#two", "Second", 1),
      candidate("mailto:no@example.test", "Mail", 2),
      candidate("/other", "Other", 3),
      ...extra,
    ],
    extraction_rejections: [],
  }, { now: () => new Date(NOW), provider, store: async () => "a".repeat(32) });
}

function normalized(value) {
  if (Array.isArray(value)) return value.map(normalized);
  if (typeof value !== "object" || value === null) {
    return typeof value === "string" && value.startsWith("candidate:")
      ? "candidate:MODE" : value;
  }
  return Object.fromEntries(Object.entries(value).map(([key, item]) => [
    key,
    key === "mode" ? "MODE" : normalized(item),
  ]));
}

test("actual Live emits only ordered atoms and executes one machine-issued provider batch", async () => {
  const operation = await liveOperation();
  assert.deepEqual(operation.input, {
    version: 1,
    kind: "live_page",
    analyzed_at: NOW,
    base_url: BASE,
    document_url: BASE,
  });
  assert.deepEqual(operation.journal.map(({ effect }) => effect.kind),
    ["EXTRACT_HTML", "OBSERVE_PROVIDER"]);
  const extraction = operation.journal[0];
  assert.deepEqual(extraction.effect.body, { kind: "rendered_anchors" });
  assert.deepEqual(extraction.fact.atoms.map(({ kind, href, text }) => ({ kind, href, text })), [
    { kind: "ANCHOR", href: "/same#one", text: "First" },
    { kind: "ANCHOR", href: "/same#two", text: "Second" },
    { kind: "ANCHOR", href: "mailto:no@example.test", text: "Mail" },
    { kind: "ANCHOR", href: "/other", text: "Other" },
  ]);
  for (const forbidden of ["occurrence_index", "target_ordinal", "canonical_url",
    "accepted_targets", "results", "limitations"]) {
    assert.equal(JSON.stringify(extraction.fact).includes(`"${forbidden}"`), false, forbidden);
  }
  const observation = operation.journal[1];
  assert.equal(observation.effect.batch.length, 2);
  assert.deepEqual(observation.fact.batch.map(({ queried_target }) => queried_target),
    ["https://watch.example/same", "https://watch.example/other"]);
});

test("Live server and generated browser replay have exact closed mutation parity", async () => {
  const operation = await liveOperation();
  const left = complete(server, operation);
  const right = complete(browser, operation);
  assert.deepEqual(right, left);
  let structural = 0;
  for (const mutant of [
    ...oneFieldMutants(operation.input).map((item) => ({ ...item, input: item.value,
      journal: left.journal })),
    ...oneFieldMutants(left.journal).map((item) => ({ ...item, input: operation.input,
      journal: item.value })),
  ]) {
    const serverResult = outcome(() => server.replayScanMachine(mutant.input, mutant.journal));
    assert.deepEqual(outcome(() => browser.replayScanMachine(mutant.input, mutant.journal)),
      serverResult, mutant.detail);
    if (mutant.kind === "add" || mutant.kind === "delete") {
      structural += 1;
      assert.notEqual(serverResult[0], "ok", mutant.detail);
    } else if (serverResult[0] === "ok" && !isDeepStrictEqual(serverResult[1], left.exchange)) {
      assert.throws(() => server.verifyScanExchange(mutant.input, mutant.journal,
        left.exchange), mutant.detail);
    }
  }
  for (const mutant of oneFieldMutants(left.exchange)) {
    const serverResult = outcome(() => server.verifyScanExchange(
      operation.input, left.journal, mutant.value));
    assert.notEqual(serverResult[0], "ok", mutant.detail);
    assert.deepEqual(outcome(() => browser.verifyScanExchange(
      operation.input, left.journal, mutant.value)), serverResult, mutant.detail);
  }
  assert.ok(structural > 100);
});

test("equivalent Paste and Live primitive sets normalize to one exchange", async () => {
  const live = complete(server, await liveOperation());
  const paste = complete(server, await executePasteScan({
    mode: "html",
    base_url: BASE,
    html: '<a href="/same#one">First</a><a href="/same#two">Second</a>' +
      '<a href="mailto:no@example.test">Mail</a><a href="/other">Other</a>',
  }, { now: () => new Date(NOW), provider }));
  assert.deepEqual(normalized(live.exchange), normalized(paste.exchange));
  assert.deepEqual(live.exchange.receipt.targets[0].occurrences.map(
    ({ occurrence_index, raw_href, anchor_text }) => ({
      occurrence_index, raw_href, anchor_text,
    })), [
    { occurrence_index: 0, raw_href: "/same#one", anchor_text: "First" },
    { occurrence_index: 1, raw_href: "/same#two", anchor_text: "Second" },
  ]);
});

test("adding a delayed rendered anchor changes the machine facts and exchange", async () => {
  const before = complete(server, await liveOperation());
  const after = complete(server, await liveOperation([
    candidate("/delayed", "Delayed", 4),
  ]));
  assert.notDeepEqual(after.journal[0].fact, before.journal[0].fact);
  assert.equal(before.exchange.receipt.targets.some(
    ({ canonical_url }) => canonical_url.endsWith("/delayed")), false);
  assert.equal(after.exchange.receipt.targets.some(
    ({ canonical_url }) => canonical_url.endsWith("/delayed")), true);
});

test("mixed truncation retains both summary categories and duplicate IDs reject", async () => {
  const candidates = Array.from({ length: 16 }, (_, index) =>
    candidate(`/mixed-${index}`, `Mixed ${index}`, index));
  const request = {
    document_url: BASE,
    observed_at: NOW,
    candidates: [...candidates, candidate("mailto:no@example.test", "Mail", 16)],
    extraction_rejections: [],
  };
  const { executeLiveScan } = await import("../dist/worker/live.js");
  let serial = 0;
  const receipt = await executeLiveScan(request, {
    now: () => new Date(NOW),
    store: async () => (++serial).toString(16).padStart(32, "0"),
  });
  assert.deepEqual([
    receipt.accepted_targets,
    receipt.rejected_candidates,
    receipt.targets.length,
    receipt.rejections.length,
    receipt.scan_ids.length,
    receipt.truncated,
  ], [16, 1, 16, 1, 16, true]);
  await assert.rejects(executeLiveScan(request, {
    now: () => new Date(NOW),
    store: async () => "d".repeat(32),
  }), /invalid allocated ID/);
});
