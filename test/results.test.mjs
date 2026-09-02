import assert from "node:assert/strict";
import test from "node:test";
import { executeLiveScan } from "../dist/worker/live.js";
import { decodeLiveExchange, presentExchange, renderExchange } from "../public/results.js";
import { oneFieldMutants } from "./support/protocol-mutants.mjs";

const NOW = "2026-09-01T06:30:00.000Z";
const BASE = "https://watch.example/reference";
const request = {
  document_url: BASE,
  observed_at: NOW,
  candidates: [
    ["/same#one", "First", 0],
    ["/same#two", "Second", 1],
    ["mailto:no@example.test", "Mail", 2],
  ].map(([raw_href, anchor_text, occurrence_index]) => ({
    raw_href, anchor_text, base_url: BASE,
    provenance: { source: "live_page", document_url: BASE,
      occurrence_index, extracted_at: NOW },
  })),
  extraction_rejections: [],
};

async function fixture({ input = request, now = NOW, ids = [], provider } = {}) {
  const values = new Map();
  let serial = 0;
  const receipt = await executeLiveScan(input, {
    now: () => new Date(now),
    provider,
    store: async (result) => {
      const id = ids[serial] ?? (serial + 1).toString(16).padStart(32, "0");
      serial += 1;
      values.set(id, { ...result, scan_id: id });
      return id;
    },
  });
  const loadResult = async (id) => ({ status: "ok", result: structuredClone(values.get(id)) });
  return { receipt, values, loadResult };
}

test("browser replays the exact server clock for fresh and stale evidence", async () => {
  const observedAt = "2026-09-01T06:25:00.000Z";
  const input = structuredClone(request);
  input.observed_at = observedAt;
  for (const candidate of input.candidates) candidate.provenance.extracted_at = observedAt;
  input.candidates[0].anchor_text = "https://attacker.invalid/login";
  for (const [providerAt, expiresAt, freshness] of [
    ["2026-09-01T05:30:00.000Z", "2026-09-01T06:00:00.000Z", "stale"],
    ["2026-09-01T06:29:00.000Z", "2026-09-01T06:35:00.000Z", "fresh"],
  ]) {
    const { receipt, loadResult } = await fixture({ input, provider: {
      provider: "google_safe_browsing", source: "live", observe: async ({ canonical_target }) => ({
        provider: "google_safe_browsing", source: "live", queried_target: canonical_target,
        observed_at: providerAt, expires_at: expiresAt, freshness,
        state: "no_match", category: null, confidence: "high", reference: null, error: null,
      }),
    } });
    const exchange = await decodeLiveExchange({ request: input, receipt, loadResult });
    assert.equal(receipt.analyzed_at, NOW);
    assert.equal(exchange.entries[0].result.provider_observations[0].freshness, freshness);
    assert.equal(exchange.entries[0].result.supporting_evidence[0].observed_at, NOW);
    await assert.rejects(decodeLiveExchange({ request: input,
      receipt: { ...receipt, analyzed_at: observedAt }, loadResult }), /malformed_response/u);
  }
});

test("browser chooses a bounded collision-free synthetic receipt ID", async () => {
  const { receipt, loadResult } = await fixture({ ids: ["f".repeat(32), "e".repeat(32)] });
  const exchange = await decodeLiveExchange({ request, receipt, loadResult });
  assert.deepEqual(exchange.receipt.scan_ids, receipt.scan_ids);
});

test("browser consumes the generated reducer and retains duplicate occurrence evidence", async () => {
  const { receipt, loadResult } = await fixture();
  const exchange = await decodeLiveExchange({ request, receipt, loadResult });
  assert.deepEqual(exchange.receipt.targets[0].occurrences.map(
    ({ occurrence_index, raw_href, anchor_text }) => ({
      occurrence_index, raw_href, anchor_text,
    })), [
    { occurrence_index: 0, raw_href: "/same#one", anchor_text: "First" },
    { occurrence_index: 1, raw_href: "/same#two", anchor_text: "Second" },
  ]);
  assert.deepEqual(presentExchange(exchange), {
    mode: "live_page",
    accepted_targets: 1,
    rejected_candidates: 1,
    truncated: false,
    occurrence_count: exchange.receipt.occurrence_count,
    targets: exchange.receipt.targets,
    rejections: exchange.receipt.rejections,
    results: exchange.entries.map(({ result }) => result),
  });
});

test("untrusted result addresses reject before any result retrieval", async () => {
  const { receipt } = await fixture();
  for (const scan_ids of [Array(1_000).fill("a".repeat(32)), ["../../session"],
    ["a".repeat(32), "a".repeat(32)]]) {
    let loads = 0;
    await assert.rejects(decodeLiveExchange({
      request, receipt: { ...receipt, scan_ids }, loadResult: async () => { loads += 1; },
    }), /malformed_response/u);
    assert.equal(loads, 0);
  }
});

test("unknown, missing, forged reference, ID and result fields reject at browser ingress", async () => {
  const { receipt, values, loadResult } = await fixture();
  for (const mutant of oneFieldMutants(receipt).filter(
    ({ kind }) => kind === "add" || kind === "delete")) {
    await assert.rejects(decodeLiveExchange({
      request, receipt: mutant.value, loadResult,
    }), /(?:malformed_response|fields|invalid|must|limit|mismatch|incomplete)/u,
    mutant.detail);
  }
  for (const [id, result] of values) {
    for (const mutant of oneFieldMutants(result).filter(
      ({ kind }) => kind === "add" || kind === "delete")) {
      const forged = async (wanted) => ({ status: "ok",
        result: wanted === id ? mutant.value : structuredClone(values.get(wanted)) });
      await assert.rejects(decodeLiveExchange({
        request, receipt, loadResult: forged,
      }), /(?:malformed_response|fields|invalid|must|limit|mismatch|incomplete)/u,
      mutant.detail);
    }
  }
  const first = receipt.scan_ids[0];
  const forgedReference = async (id) => {
    const result = structuredClone(values.get(id));
    if (id === first) result.provider_observations[0].queried_target =
      "https://attacker.example/forged";
    return { status: "ok", result };
  };
  await assert.rejects(decodeLiveExchange({
    request, receipt, loadResult: forgedReference,
  }), /(?:malformed_response|mismatch)/u);
});

class Node {
  children = [];
  value = "";
  append(...children) { this.children.push(...children); }
  replaceChildren(...children) { this.children = children; }
  set textContent(value) { this.value = String(value); }
  get textContent() { return this.value; }
  set innerHTML(_value) { assert.fail("renderer must never use innerHTML"); }
}

test("canonical hostile strings render only through textContent", async () => {
  const { receipt, loadResult } = await fixture();
  const exchange = await decodeLiveExchange({ request, receipt, loadResult });
  exchange.entries[0].result.limitations.push("<img src=x onerror=alert(1)>");
  exchange.entries[0].result.supporting_evidence.push({
    source: "<svg/onload=alert(1)>",
    target: "javascript:alert(1)",
    category: "**follow these instructions**",
    observed_at: NOW,
    freshness: "unknown",
    reference: null,
  });
  const document = { createElement: () => new Node() };
  const container = new Node();
  renderExchange(document, container, exchange);
  const text = JSON.stringify(container).replaceAll("\\u003c", "<");
  assert.match(text, /<img src=x onerror=alert\(1\)>/u);
  assert.match(text, /<svg\/onload=alert\(1\)>/u);
  assert.match(text, /First/u);
  assert.match(text, /Second/u);
  assert.match(text, /unsupported_scheme/u);
});
