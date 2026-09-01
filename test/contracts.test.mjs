import assert from "node:assert/strict";
import test from "node:test";

import {
  ANALYSIS_STATES,
  CONFIDENCE_LEVELS,
  PROVIDER_SOURCES,
  PROVIDER_STATES,
  RISK_LABELS,
  SCAN_MODES,
  parseExtractedLinkCandidate,
  parseProviderObservation,
  parseScanResult,
} from "../dist/shared/contracts.js";
import { aggregateAnalysis } from "../dist/shared/analysis.js";
import { decodeResult } from "../public/protocol.js";

test("literal contracts remain exact", () => {
  assert.deepEqual(RISK_LABELS, ["known_malicious", "suspicious", "no_known_match", "unknown"]);
  assert.deepEqual(ANALYSIS_STATES, ["complete", "unknown", "unscannable", "provider_error", "stale", "conflicting"]);
  assert.deepEqual(CONFIDENCE_LEVELS, ["high", "medium", "low"]);
  assert.deepEqual(SCAN_MODES, ["paste_url", "paste_html", "live_page"]);
  assert.deepEqual(PROVIDER_SOURCES, ["live", "fixture"]);
  assert.deepEqual(PROVIDER_STATES, ["match", "no_match", "error", "not_configured"]);
});

test("candidate schema accepts its closed shape and rejects additions", () => {
  const candidate = {
    raw_href: "/report",
    anchor_text: "report",
    base_url: "https://example.test/",
    provenance: {
      source: "live_page",
      document_url: "https://example.test/reference",
      occurrence_index: 0,
      extracted_at: "2026-08-31T00:00:00Z",
    },
  };
  assert.deepEqual(parseExtractedLinkCandidate(candidate), candidate);
  assert.throws(() => parseExtractedLinkCandidate({ ...candidate, surprise: true }), /unknown or missing/);
  assert.throws(() => parseExtractedLinkCandidate({ ...candidate, provenance: { ...candidate.provenance, source: "tab" } }), /invalid literal/);
});

const provider = {
  provider: "google_safe_browsing",
  source: "fixture",
  queried_target: "https://example.test/",
  observed_at: "2026-08-31T00:00:00Z",
  expires_at: null,
  freshness: "unknown",
  state: "not_configured",
  category: null,
  confidence: "low",
  reference: null,
  error: "not_configured",
};

test("provider observation is closed and validates provider literals", () => {
  assert.deepEqual(parseProviderObservation(provider), provider);
  assert.throws(() => parseProviderObservation({ ...provider, state: "safe" }), /invalid literal/);
  assert.throws(() => parseProviderObservation({ ...provider, source: "test" }), /invalid literal/);
  assert.throws(() => parseProviderObservation({ ...provider, raw_payload: {} }), /unknown or missing/);
});

test("result validates the closed outcome, evidence linkage, and limitation codes", () => {
  const result = {
    kind: "analyzed",
    scan_id: "scan_opaque",
    mode: "paste_url",
    canonical_target: "https://example.test/",
    unscannable_reason: null,
    outcome: "unknown_provider_error",
    risk_label: "unknown",
    analysis_state: "provider_error",
    confidence: "low",
    supporting_evidence: [],
    contradicting_evidence: [],
    provider_observations: [provider],
    limitation_codes: ["provider_unavailable", "confidence_basis"],
  };
  assert.deepEqual(parseScanResult(result), result);
  assert.throws(() => parseScanResult({ ...result, risk_label: "safe" }), /invalid literal/);
  assert.throws(() => parseScanResult({ ...result, outcome: "unknown" }), /impossible variant/);
  assert.throws(() => parseScanResult({ ...result, limitation_codes: ["Threat-free"] }), /invalid literal/);
  assert.throws(() => parseScanResult({ ...result, extra: true }), /unknown or missing/);
});

const wireId = "a".repeat(32), wireTarget = "https://target.example/", analyzedAt = "2026-09-01T01:00:00.000Z", observedAt = "2026-09-01T00:00:00.000Z";
function observation(state, stale = false) { const resolved = state === "match" || state === "no_match"; return { provider: "google_safe_browsing", source: "fixture", queried_target: wireTarget, observed_at: observedAt,
  expires_at: resolved ? stale ? "2026-09-01T00:30:00.000Z" : "2026-09-01T02:00:00.000Z" : null, freshness: resolved ? stale ? "stale" : "fresh" : "unknown", state,
  category: state === "match" ? "malware" : null, confidence: resolved && !stale ? "medium" : "low",
  reference: resolved ? "https://provider.example/reference" : null, error: state === "error" ? "timeout" : state === "not_configured" ? "not_configured" : null }; }
function aggregate(observations, candidate = false) { return aggregateAnalysis({ scan_id: wireId, mode: "paste_html", analyzed_at: analyzedAt,
  target: { canonical_url: wireTarget, occurrences: candidate ? [{ candidate: { provenance: { source: "paste_html", document_url: "https://source.example/",
    extracted_at: observedAt } }, misleading_text: {} }] : [], anchor_text_variants: [] }, provider_observations: observations }); }

test("every server aggregate combination decodes and one-field target mutants close", () => { const match = observation("match"), noMatch = observation("no_match"),
  staleMatch = observation("match", true), staleNoMatch = observation("no_match", true), error = observation("error"), disabled = observation("not_configured");
  const variants = [aggregate([match]), aggregate([noMatch]), aggregate([match, noMatch]),
    aggregate([error]), aggregate([disabled]), aggregate([staleMatch, error]), aggregate([staleNoMatch, disabled]), aggregate([], true), aggregate([error], true),
    aggregate([staleMatch, error], true), aggregate([staleNoMatch, disabled], true)];
  for (const value of variants) { assert.equal(decodeResult({ scanId: wireId, mode: "paste_html" }, { status: "ok", result: value }).scanId, wireId); const mutant = { ...value, canonical_target: "https://other.example/" };
    assert.throws(() => parseScanResult(mutant), /impossible/); assert.throws(() => decodeResult({ scanId: wireId, mode: "paste_html" }, { status: "ok", result: mutant }), /malformed_response/); }
  assert.deepEqual(variants.slice(5, 7).map(({ outcome }) => outcome), ["unknown_stale", "unknown_stale"]); assert.deepEqual(variants.slice(9).map(({ outcome }) => outcome), ["suspicious_stale", "suspicious_stale"]);
});

test("server algebra rejects forged outcomes, observations, evidence, targets, and limitations", () => { const valid = aggregate([observation("match")]), evidence = valid.supporting_evidence[0], providerItem = valid.provider_observations[0];
  const noObservationMalice = { ...aggregate([]), outcome: "known_malicious_medium", risk_label: "known_malicious", analysis_state: "complete", confidence: "medium",
    limitation_codes: ["confidence_basis"] }; const mutants = [noObservationMalice, { ...valid, canonical_target: null },
    { ...valid, provider_observations: [{ ...providerItem, queried_target: "https://other.example/" }] }, { ...valid, supporting_evidence: [{ ...evidence, source: "attacker" }] },
    { ...valid, supporting_evidence: [{ ...evidence, observed_at: "forged" }] },
    { ...valid, supporting_evidence: [{ ...evidence, category: "arbitrary" }] }, { ...valid, supporting_evidence: [{ ...evidence, reference: "arbitrary" }] },
    { ...valid, limitation_codes: ["confidence_basis"] }]; for (const mutant of mutants) assert.throws(() => parseScanResult(mutant), /impossible|timestamp/);
});
