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

test("result validates distinct risk, state, confidence, evidence and limitations", () => {
  const result = {
    scan_id: "scan_opaque",
    mode: "paste_url",
    canonical_target: "https://example.test/",
    risk_label: "unknown",
    analysis_state: "provider_error",
    confidence: "low",
    supporting_evidence: [],
    contradicting_evidence: [],
    provider_observations: [provider],
    limitations: ["Provider is not configured."],
  };
  assert.deepEqual(parseScanResult(result), result);
  assert.throws(() => parseScanResult({ ...result, risk_label: "safe" }), /invalid literal/);
  assert.throws(() => parseScanResult({ ...result, limitations: [], extra: true }), /unknown or missing/);
});
