import assert from "node:assert/strict";
import test from "node:test";
import { decodeReceipt, decodeResult } from "../public/protocol.js";
import { sessionClientFor } from "../public/session-client.js";
import { createSupportingTools } from "../public/webmcp.js";
const id = "a".repeat(32); const target = "https://example.com/";
const paste = (mode = "paste_html") => ({ mode, scan_ids: [id], accepted_targets: 1,
  rejected_candidates: 0, truncated: false, unscannable_reason: null,
  ...(mode === "paste_url" ? { fetch_evidence: { requested_url: target, final_url: target,
    redirect_chain: [], validated_hops: [{ hostname: "example.com", address_count: 1 }] } } : {}) });
const result = (overrides = {}) => ({ kind: "analyzed", scan_id: id, mode: "paste_html",
  canonical_target: target, unscannable_reason: null, outcome: "unknown", risk_label: "unknown",
  analysis_state: "unknown", confidence: "low", supporting_evidence: [], contradicting_evidence: [],
  provider_observations: [], limitation_codes: ["no_provider_observation", "confidence_basis"], ...overrides });
const envelope = (value = result()) => ({ status: "ok", result: value });
test("all receipt variants are exact and request-bound", () => {
  assert.equal(decodeReceipt({ kind: "paste_url", requestedUrl: target }, paste("paste_url")).mode, "paste_url");
  assert.equal(decodeReceipt({ kind: "paste_html" }, paste()).mode, "paste_html");
  const live = { mode: "live_page", scan_ids: [id], observed_candidates: 1, accepted_targets: 1, rejected_candidates: 0,
    truncated: false, page_evidence_trust: "untrusted", targets: [{
      canonical_url: target, occurrence_indices: [0], anchor_text_variants: ["one"] }], rejections: [] };
  assert.equal(decodeReceipt({ kind: "live_page", observedCandidates: 1 }, live).mode, "live_page");
  for (const [descriptor, mutant] of [
    [{ kind: "paste_html" }, paste("paste_url")],
    [{ kind: "paste_url", requestedUrl: "https://other.example/" }, paste("paste_url")],
    [{ kind: "live_page", observedCandidates: 2 }, live],
    [{ kind: "paste_html" }, { ...paste(), unscannable_reason: "timeout", accepted_targets: 0 }],
    [{ kind: "paste_html" }, { ...paste(), extra: true }],
  ]) assert.throws(() => decodeReceipt(descriptor, mutant), /malformed_response/);
}); test("result variants reject every independent authority mutation", () => {
  assert.equal(decodeResult({ scanId: id, mode: "paste_html", truncated: false }, envelope()).risk, "unknown");
  const rejected = result({ kind: "unscannable", canonical_target: null, unscannable_reason: "no_candidates", outcome: "unscannable", analysis_state: "unscannable", limitation_codes: ["confidence_basis"] }); assert.equal(decodeResult({ scanId: id, mode: "paste_html" }, envelope(rejected)).state, "unscannable");
  const observed_at = "2026-09-01T00:00:00.000Z"; const expires_at = "2026-09-01T00:01:00.000Z"; const provider = { provider: "google_safe_browsing", source: "live", queried_target: target, observed_at, expires_at, freshness: "fresh", state: "match", category: "malware",
    confidence: "medium", reference: "https://transparencyreport.google.com/safe-browsing/search", error: null };
  const evidence = { source: "live:google_safe_browsing", target, category: "malware", observed_at, freshness: "fresh", reference: provider.reference, provider_observation_index: 0 };
  const valid = result({ mode: "paste_url", outcome: "known_malicious_medium", risk_label: "known_malicious", analysis_state: "complete", confidence: "medium", supporting_evidence: [evidence], provider_observations: [provider], limitation_codes: ["provider_match_scope", "confidence_basis"] });
  assert.equal(decodeResult({ scanId: id, mode: "paste_url" }, envelope(valid)).risk, "known_malicious");
  for (const mutant of [{ ...valid, scan_id: "b".repeat(32) }, { ...valid, mode: "live_page" },
    { ...valid, outcome: "unknown" }, { ...valid, risk_label: "unknown" },
    { ...valid, supporting_evidence: [{ ...evidence, provider_observation_index: 1 }] },
    { ...valid, provider_observations: [{ ...provider, reference: null }] },
    { ...valid, limitation_codes: ["Threat-free"] }, { ...valid, attacker: true }]) assert.throws(() => decodeResult({ scanId: id, mode: "paste_url" }, envelope(mutant)), /malformed_response/);
}); test("supporting tools retain literal bounded contracts", async () => {
  const page = { querySelector: () => ({ checked: true }) }; const commits = []; const fetcher = async (path) => path === "/api/session" ? Response.json({ authenticated: true, csrf_token: "c".repeat(32), expires_at: "2026-09-01T13:00:00.000Z" }) : Response.json(envelope()); const tools = createSupportingTools(fetcher, page); sessionClientFor(page, fetcher).connect({ commit: (value) => commits.push(value) });
  assert.deepEqual(tools.map(({ name }) => name), ["scan_url", "get_scan_result"]);
  assert.ok(tools.every((tool) => tool.inputSchema.additionalProperties === false && tool.annotations.readOnlyHint && tool.annotations.untrustedContentHint));
  await assert.rejects(tools[0].execute({ targetUrl: target, extra: true }), /invalid_arguments/);
  await assert.rejects(tools[1].execute({ scanId: "raw" }), /invalid_arguments/);
  await tools[1].execute({ scanId: id }); assert.equal(commits.length, 1);
});
