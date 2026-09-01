import assert from "node:assert/strict";
import test from "node:test";

import {
  ANALYSIS_LIMITS,
  aggregateAnalysis,
} from "../dist/shared/analysis.js";
import {
  ANALYSIS_STATES,
  CONFIDENCE_LEVELS,
  FRESHNESS_STATES,
  PROVIDER_ERROR_CODES,
  PROVIDER_STATES,
  RISK_LABELS,
  parseProviderObservation,
  parseScanResult,
} from "../dist/shared/contracts.js";
import { FixtureProviderAdapter } from "../dist/worker/providers/fixture.js";
import { PROVIDER_ADAPTER_LIMITS } from "../dist/worker/providers/types.js";

const canonicalTarget = "https://example.test/path?q=1";
const now = "2026-09-01T00:10:00.000Z";
const observed = "2026-09-01T00:00:00.000Z";
const futureExpiry = "2026-09-01T00:10:00.001Z";
const expired = "2026-09-01T00:09:59.999Z";

function target({ misleading = false, url = canonicalTarget } = {}) {
  return {
    canonical_url: url,
    scheme: "https",
    hostname_ascii: "example.test",
    display_hostname: "example.test",
    occurrences: [{
      candidate: {
        raw_href: url,
        anchor_text: misleading ? "https://accounts.example.test/login" : "ordinary link",
        base_url: "https://source.example/",
        provenance: {
          source: "live_page",
          document_url: "https://source.example/reference",
          occurrence_index: 0,
          extracted_at: observed,
        },
      },
      misleading_text: misleading ? {
        displayed_text: "https://accounts.example.test/login",
        displayed_target: "https://accounts.example.test/login",
        linked_target: url,
      } : null,
    }],
    anchor_text_variants: misleading
      ? ["https://accounts.example.test/login"]
      : ["ordinary link"],
  };
}

async function observe(scenario, request = { canonical_target: canonicalTarget, requested_at: now }) {
  const adapter = new FixtureProviderAdapter(scenario);
  assert.equal(adapter.source, "fixture");
  assert.equal(adapter.provider, "google_safe_browsing");
  const result = await adapter.observe(request);
  return parseProviderObservation(result);
}

function aggregate(provider_observations, overrides = {}) {
  return aggregateAnalysis({
    scan_id: "scan_fixture",
    mode: "live_page",
    analyzed_at: now,
    target: target(),
    provider_observations,
    ...overrides,
  });
}

function assertNoSafetyClaim(value, name) {
  assert.doesNotMatch(
    JSON.stringify(value),
    /\b(is safe|safe to|clean|harmless|no threats?)\b/i,
    name,
  );
}

const positive = {
  outcome: "match",
  category: "social_engineering",
  observed_at: observed,
  expires_at: futureExpiry,
  reference: "https://provider.example/reference/positive",
};
const noMatch = {
  outcome: "no_match",
  observed_at: observed,
  expires_at: futureExpiry,
  reference: "https://provider.example/reference/no-match",
};

test("fixture matrix normalizes every provider outcome without owning a verdict", async () => {
  const cases = [
    ["positive", positive, "match", null, "fresh", "medium"],
    ["no-match", noMatch, "no_match", null, "fresh", "medium"],
    ["timeout", { outcome: "timeout" }, "error", "timeout", "unknown", "low"],
    ["quota", { outcome: "quota" }, "error", "quota", "unknown", "low"],
    ["unavailable", { outcome: "unavailable" }, "error", "unavailable", "unknown", "low"],
    ["malformed", { outcome: "malformed_response" }, "error", "malformed_response", "unknown", "low"],
    ["not configured", { outcome: "not_configured" }, "not_configured", "not_configured", "unknown", "low"],
    ["stale positive", { ...positive, expires_at: expired }, "match", null, "stale", "low"],
    ["stale no-match", { ...noMatch, expires_at: expired }, "no_match", null, "stale", "low"],
    ["freshness unavailable", { ...noMatch, expires_at: null }, "no_match", null, "unknown", "low"],
  ];

  for (const [name, scenario, state, error, freshness, confidence] of cases) {
    const observation = await observe(scenario);
    assert.equal(observation.state, state, name);
    assert.equal(observation.error, error, name);
    assert.equal(observation.freshness, freshness, name);
    assert.equal(observation.confidence, confidence, name);
    assert.equal("risk_label" in observation, false, name);
    assert.equal("analysis_state" in observation, false, name);
    assert.equal("raw_payload" in observation, false, name);
  }
});

test("aggregate matrix covers positive, no-match, failures, stale, empty and missing", async () => {
  const positiveObservation = await observe(positive);
  const noMatchObservation = await observe(noMatch);
  const cases = [
    ["positive", [positiveObservation], "known_malicious", "complete", "medium"],
    ["no-match", [noMatchObservation], "no_known_match", "complete", "medium"],
    ["timeout", [await observe({ outcome: "timeout" })], "unknown", "provider_error", "low"],
    ["quota", [await observe({ outcome: "quota" })], "unknown", "provider_error", "low"],
    ["unavailable", [await observe({ outcome: "unavailable" })], "unknown", "provider_error", "low"],
    ["malformed", [await observe({ outcome: "malformed_response" })], "unknown", "provider_error", "low"],
    ["not configured", [await observe({ outcome: "not_configured" })], "unknown", "provider_error", "low"],
    ["stale positive", [await observe({ ...positive, expires_at: expired })], "unknown", "stale", "low"],
    ["stale no-match", [await observe({ ...noMatch, expires_at: expired })], "unknown", "stale", "low"],
    ["empty", [], "unknown", "unknown", "low"],
    ["missing", undefined, "unknown", "unknown", "low"],
  ];

  for (const [name, observations, label, state, confidence] of cases) {
    const result = aggregate(observations);
    assert.equal(result.risk_label, label, name);
    assert.equal(result.analysis_state, state, name);
    assert.equal(result.confidence, confidence, name);
    assert.deepEqual(parseScanResult(result), result, name);
    if (name !== "positive") assertNoSafetyClaim(result, name);
  }
});

test("one current recognized positive supports known malicious with qualified evidence", async () => {
  const observation = await observe(positive);
  const result = aggregate([observation]);

  assert.equal(result.risk_label, "known_malicious");
  assert.deepEqual(result.supporting_evidence, [{
    source: "google_safe_browsing",
    target: canonicalTarget,
    category: "social_engineering",
    observed_at: observed,
    freshness: "fresh",
    reference: positive.reference,
  }]);
  assert.deepEqual(result.contradicting_evidence, []);
  assert.match(result.limitations.join(" "), /qualified evidence/i);
});

test("current no-match is only no-known-match and never a safety claim", async () => {
  const result = aggregate([await observe(noMatch)]);
  assert.equal(result.risk_label, "no_known_match");
  assert.equal(result.supporting_evidence[0].category, "no_known_match");
  assert.deepEqual(result.contradicting_evidence, []);

  assertNoSafetyClaim(result, "no-match result");
});

test("current material disagreement is conflicting and preserves both sides", async () => {
  const match = await observe(positive);
  const no_match = await observe(noMatch);
  const result = aggregate([no_match, match]);

  assert.equal(result.risk_label, "known_malicious");
  assert.equal(result.analysis_state, "conflicting");
  assert.equal(result.confidence, "low");
  assert.deepEqual(result.supporting_evidence.map((item) => item.category), ["social_engineering"]);
  assert.deepEqual(result.contradicting_evidence.map((item) => item.category), ["no_known_match"]);
});

test("misleading URL-like text independently supports suspicious and records extraction origin", () => {
  const suspiciousOnly = aggregate(undefined, { target: target({ misleading: true }) });
  assert.equal(suspiciousOnly.risk_label, "suspicious");
  assert.equal(suspiciousOnly.analysis_state, "unknown");
  assert.equal(suspiciousOnly.confidence, "low");
  assert.deepEqual(suspiciousOnly.supporting_evidence, [{
    source: "candidate:live_page",
    target: canonicalTarget,
    category: "misleading_url_like_text",
    observed_at: observed,
    freshness: "fresh",
    reference: "https://source.example/reference",
  }]);
});

test("confidence describes completeness and agreement rather than harm likelihood", async () => {
  const positiveResult = aggregate([await observe(positive)]);
  const noMatchResult = aggregate([await observe(noMatch)]);
  const independentAgreement = aggregate([await observe(positive)], {
    target: target({ misleading: true }),
  });
  const duplicatePositive = aggregate([
    await observe(positive),
    await observe(positive),
  ]);

  assert.equal(positiveResult.confidence, noMatchResult.confidence);
  assert.equal(duplicatePositive.confidence, "medium");
  assert.equal(independentAgreement.confidence, "high");
  assert.match(independentAgreement.limitations.at(-1), /completeness, independence, freshness, and agreement/i);
  assert.match(independentAgreement.limitations.at(-1), /not likelihood of harm/i);
});

test("freshness and adapter bounds use exact conservative boundaries", async () => {
  const atExpiry = await observe({ ...positive, expires_at: now });
  const oneMillisecondCurrent = await observe({ ...positive, expires_at: futureExpiry });
  assert.equal(atExpiry.freshness, "stale");
  assert.equal(aggregate([atExpiry]).analysis_state, "stale");
  assert.equal(oneMillisecondCurrent.freshness, "fresh");
  assert.equal(aggregate([oneMillisecondCurrent]).analysis_state, "complete");

  const prefix = "https://example.test/";
  const exactTarget = prefix + "a".repeat(PROVIDER_ADAPTER_LIMITS.max_target_chars - prefix.length);
  const exactReference = "r".repeat(PROVIDER_ADAPTER_LIMITS.max_reference_chars);
  const exact = await observe(
    { ...noMatch, reference: exactReference },
    { canonical_target: exactTarget, requested_at: now },
  );
  assert.equal(exact.queried_target.length, PROVIDER_ADAPTER_LIMITS.max_target_chars);
  assert.equal(exact.reference.length, PROVIDER_ADAPTER_LIMITS.max_reference_chars);

  await assert.rejects(
    observe(noMatch, { canonical_target: `${exactTarget}a`, requested_at: now }),
    /exceeds provider adapter limits/,
  );
  const oversizedReference = await observe({
    ...noMatch,
    reference: `${exactReference}r`,
  });
  assert.equal(oversizedReference.error, "malformed_response");
});

test("aggregate re-derives freshness, rejects overflow, and does not mutate or depend on order", async () => {
  const match = await observe(positive);
  const no_match = await observe(noMatch);
  const falselyFresh = {
    ...await observe({ ...positive, expires_at: expired }),
    freshness: "fresh",
    confidence: "high",
  };
  const original = structuredClone([no_match, match]);
  const first = aggregate([no_match, match]);
  const second = aggregate([match, no_match]);

  const twoOrigins = target({ misleading: true });
  const otherOccurrence = structuredClone(twoOrigins.occurrences[0]);
  otherOccurrence.candidate.provenance.document_url = "https://another.example/reference";
  otherOccurrence.candidate.provenance.occurrence_index = 1;
  const forwardTarget = { ...twoOrigins, occurrences: [twoOrigins.occurrences[0], otherOccurrence] };
  const reverseTarget = { ...twoOrigins, occurrences: [otherOccurrence, twoOrigins.occurrences[0]] };
  const frozenInput = {
    scan_id: "scan_fixture",
    mode: "live_page",
    analyzed_at: now,
    target: Object.freeze(forwardTarget),
    provider_observations: Object.freeze([Object.freeze(match)]),
  };

  assert.deepEqual(first, second);
  assert.deepEqual([no_match, match], original);
  assert.deepEqual(
    aggregate(undefined, { target: forwardTarget }),
    aggregate(undefined, { target: reverseTarget }),
  );
  assert.doesNotThrow(() => aggregateAnalysis(frozenInput));
  assert.equal(aggregate([falselyFresh]).analysis_state, "stale");
  assert.equal(aggregate([falselyFresh]).provider_observations[0].confidence, "low");
  assert.doesNotThrow(() => aggregate(Array(ANALYSIS_LIMITS.max_provider_observations).fill(match)));
  assert.throws(
    () => aggregate(Array(ANALYSIS_LIMITS.max_provider_observations + 1).fill(match)),
    /too many provider observations/,
  );
});

test("malformed normalized shapes fail closed and raw fixture fields cannot escape", async () => {
  const scenario = { ...positive, raw_payload: { secret: "must-not-escape" } };
  const observation = await observe(scenario);
  assert.equal(JSON.stringify(observation).includes("must-not-escape"), false);
  assert.equal(Object.keys(observation).length, 10);

  const malformedMatch = { ...observation, category: "invented_category" };
  const result = aggregate([malformedMatch]);
  assert.equal(result.risk_label, "unknown");
  assert.equal(result.analysis_state, "provider_error");
  assert.equal(result.provider_observations[0].error, "malformed_response");
  assert.equal(JSON.stringify(result).includes("invented_category"), false);
});

test("unscannable and all literal dimensions validate through runtime contracts", async () => {
  const unscannable = aggregateAnalysis({
    scan_id: "scan_rejected",
    mode: "paste_url",
    analyzed_at: now,
    target: null,
    unscannable_reason: "unsupported_scheme",
  });
  assert.equal(unscannable.analysis_state, "unscannable");
  assert.deepEqual(parseScanResult(unscannable), unscannable);

  const results = [
    aggregate([await observe(positive)]),
    aggregate([await observe(noMatch)]),
    aggregate([await observe({ outcome: "timeout" })]),
    aggregate([await observe({ ...positive, expires_at: expired })]),
    aggregate([await observe(positive), await observe(noMatch)]),
    aggregate(undefined, { target: target({ misleading: true }) }),
    aggregate([await observe(positive)], { target: target({ misleading: true }) }),
    unscannable,
  ];
  const dimensions = (field) => [...new Set(results.map((result) => result[field]))].sort();
  assert.deepEqual(dimensions("risk_label"), [...RISK_LABELS].sort());
  assert.deepEqual(dimensions("analysis_state"), [...ANALYSIS_STATES].sort());
  assert.deepEqual(dimensions("confidence"), [...CONFIDENCE_LEVELS].sort());

  const observations = await Promise.all([
    observe(positive), observe(noMatch), observe({ outcome: "timeout" }),
    observe({ outcome: "quota" }), observe({ outcome: "unavailable" }),
    observe({ outcome: "malformed_response" }), observe({ outcome: "not_configured" }),
    observe({ ...positive, expires_at: expired }), observe({ ...noMatch, expires_at: null }),
  ]);
  const observationDimensions = (field) =>
    [...new Set(observations.map((item) => item[field]))].filter((item) => item !== null).sort();
  assert.deepEqual(observationDimensions("state"), [...PROVIDER_STATES].sort());
  assert.deepEqual(observationDimensions("freshness"), [...FRESHNESS_STATES].sort());
  assert.deepEqual(observationDimensions("error"), [...PROVIDER_ERROR_CODES].sort());
});
