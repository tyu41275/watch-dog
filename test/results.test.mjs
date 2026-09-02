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

async function fixture() {
  const values = new Map();
  let serial = 0;
  const receipt = await executeLiveScan(request, {
    now: () => new Date(NOW),
    store: async (result) => {
      const id = (++serial).toString(16).padStart(32, "0");
      values.set(id, { ...result, scan_id: id });
      return id;
    },
  });
  const loadResult = async (id) => ({ status: "ok", result: structuredClone(values.get(id)) });
  return { receipt, values, loadResult };
}

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
    results: exchange.entries.map(({ result }) => result),
  });
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
});
