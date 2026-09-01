import assert from "node:assert/strict";
import test from "node:test";
import { captureRealProducerCorpus } from "./support/real-producer-corpus.mjs";
import { changedTopLevel, oneFieldMutants } from "./support/protocol-mutants.mjs";

const corpus = await captureRealProducerCorpus();
const stores = (operation) => corpus.events.stores.filter((event) => event.operation === operation);

test("real compiled producer seams capture initiating facts and observable outputs", () => {
  assert.deepEqual(Object.keys(corpus.contexts).sort(), ["analysis", "coordinator", "live", "paste_256", "paste_html", "paste_url", "provider", "redirect_loop"].sort());
  assert.equal(corpus.outputs.provider.match.state, "match");
  assert.equal(corpus.outputs.provider.no_match.state, "no_match");
  assert.deepEqual(corpus.outputs.analysis.provider_observations.map(({ state }) => state), ["match", "no_match"], "analysis deduplicates and orders actual observations");
  assert.deepEqual(corpus.outputs.analysis.supporting_evidence.map(({ source }) => source), ["candidate:live_page", "candidate:paste_html", "fixture:google_safe_browsing"]);
  assert.deepEqual(corpus.outputs.analysis.contradicting_evidence.map(({ source }) => source), ["fixture:google_safe_browsing"]);
  assert.deepEqual(corpus.facts.analysis_target.occurrences.map(({ candidate: value }) => value.provenance.occurrence_index), [1, 0], "producer occurrence order is retained as a fact");
  assert.equal(corpus.outputs.paste_url.mode, "paste_url");
  assert.equal(corpus.outputs.paste_url.accepted_targets, 1);
  assert.equal(corpus.outputs.paste_html.mode, "paste_html");
  assert.deepEqual([corpus.outputs.paste_html.accepted_targets, corpus.outputs.paste_html.rejected_candidates], [2, 1]);
  assert.ok(corpus.events.provider_requests.some(({ operation }) => operation === "paste_url"));
  assert.ok(corpus.events.provider_requests.some(({ operation }) => operation === "paste_html"));
  assert.ok(corpus.events.provider_requests.some(({ operation }) => operation === "live"));
});

test("real safe fetch preserves the bounded A to B to A redirect-loop trace", () => {
  const loop = corpus.outputs.redirect_loop;
  assert.equal(loop.unscannable_reason, "redirect_loop");
  assert.deepEqual(loop.fetch_evidence.redirect_chain, ["https://loop.example.co/b", "https://loop.example.co/a"]);
  assert.deepEqual(loop.fetch_evidence.validated_hops, [
    { hostname: "loop.example.co", address_count: 1 },
    { hostname: "loop.example.co", address_count: 1 },
  ]);
  assert.deepEqual(corpus.events.fetch_requests.slice(-2), ["https://loop.example.co/a", "https://loop.example.co/b"]);
  assert.equal(stores("redirect_loop")[0].submitted.analysis_state, "unscannable");
});

test("real Live and Paste boundaries preserve order duplicates and truncation provenance", () => {
  const expected = { 0: [1, 0, false], 1: [1, 1, false], 15: [15, 15, false], 16: [16, 16, false], 17: [16, 17, true], 32: [16, 32, true] };
  for (const [count, [retained, accepted, truncated]] of Object.entries(expected)) {
    const receipt = corpus.outputs.live_boundaries[count];
    assert.deepEqual([receipt.scan_ids.length, receipt.accepted_targets, receipt.truncated], [retained, accepted, truncated], count);
  }
  assert.deepEqual(corpus.outputs.live.targets[0], { canonical_url: "https://watch.example/duplicate", occurrence_indices: [0, 1], anchor_text_variants: ["First label", "Second label"] });
  assert.deepEqual([corpus.outputs.live.observed_candidates, corpus.outputs.live.accepted_targets, corpus.outputs.live.scan_ids.length, corpus.outputs.live.truncated], [32, 31, 16, true]);
  assert.deepEqual([corpus.outputs.paste_256.accepted_targets, corpus.outputs.paste_256.scan_ids.length, corpus.outputs.paste_256.truncated], [256, 16, true]);
  for (const operation of ["live_boundary_17", "live_boundary_32", "paste_256"]) assert.ok(stores(operation).every(({ submitted }) => submitted.limitations.at(-1).includes("bounded results were retained")), operation);
});

test("coordinator storage creates deterministic receipt/result bindings and throttle events", () => {
  assert.ok(corpus.outputs.coordinator.pairs.length > 100);
  assert.ok(corpus.outputs.coordinator.pairs.every(({ receipt_id, result_id }) => receipt_id === result_id && /^[a-f0-9]{32}$/u.test(receipt_id)));
  assert.deepEqual(corpus.events.throttle.map(({ allowed }) => allowed), [true, true, true, true, true, false, true]);
  for (const operation of ["paste_url", "paste_html", "redirect_loop", "live"]) {
    const receipt = corpus.outputs[operation];
    assert.deepEqual(receipt.scan_ids, stores(operation).map(({ scan_id }) => scan_id));
  }
});

test("the real corpus is deterministic without consulting a future protocol decoder", async () => {
  assert.deepEqual(await captureRealProducerCorpus(), corpus);
  assert.equal(JSON.stringify(corpus).includes("protocol-core"), false);
});

test("generic one-field walker covers the frozen mutation mechanics without validity claims", () => {
  const evidenceStore = stores("paste_html").find(({ stored }) => stored.supporting_evidence.length > 1);
  assert.ok(evidenceStore);
  const sample = { receipt: corpus.outputs.paste_html, result: evidenceStore.stored, provider: corpus.outputs.provider.match, live: corpus.outputs.live, pair: corpus.outputs.coordinator.pairs[0] };
  const before = structuredClone(sample);
  const mutants = oneFieldMutants(sample, { targeted: [
    { path: ["receipt", "mode"], kind: "legal_literal", values: ["paste_url", "live_page"] },
    { path: ["receipt", "scan_ids", 0], kind: "id", values: ["f".repeat(32)] },
    { path: ["receipt", "accepted_targets"], kind: "count", values: [0, 17] },
    { path: ["receipt", "truncated"], kind: "truncation", values: [true] },
    { path: ["result", "mode"], kind: "legal_literal", values: ["paste_url", "live_page"] },
    { path: ["result", "scan_id"], kind: "id", values: ["e".repeat(32)] },
    { path: ["provider", "observed_at"], kind: "time", values: ["2026-09-01T06:30:00.001Z"] },
    { path: ["provider", "freshness"], kind: "freshness", values: ["stale", "unknown"] },
    { path: ["provider", "reference"], kind: "provider_reference", values: ["https://other.example/provider"] },
    { path: ["result", "supporting_evidence", 0, "reference"], kind: "evidence_reference", values: ["https://other.example/evidence"] },
    { path: ["live", "targets", 0, "occurrence_indices", 0], kind: "index", values: [1, 256] },
    { path: ["pair", "receipt_id"], kind: "binding", values: ["d".repeat(32)] },
  ] });
  const required = ["add", "delete", "type", "legal_literal", "bound", "order", "duplicate", "count", "truncation", "time", "freshness", "provider_reference", "evidence_reference", "index", "id", "binding"];
  const kinds = new Set(mutants.map(({ kind }) => kind));
  for (const kind of required) assert.ok(kinds.has(kind), kind);
  assert.ok(mutants.length > 500);
  assert.ok(mutants.some(({ kind, path }) => kind === "delete" && path.join(".") === "result.supporting_evidence.0.reference"));
  assert.ok(mutants.every(({ value }) => changedTopLevel(sample, value).length === 1));
  assert.deepEqual(sample, before, "walker must not mutate captured producer output");
});
