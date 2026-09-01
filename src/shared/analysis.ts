import {
  outcomeFor,
  parseProviderObservation,
  parseScanResult,
  type AnalysisState,
  type Confidence,
  type Evidence,
  type LimitationCode,
  type ProviderObservation,
  type ProviderSource,
  type RiskLabel,
  type ScanMode,
  type ScanResult,
} from "./contracts.js";
import type { CanonicalCandidateTarget } from "./candidates.js";
import type { UnscannableReason } from "./canonicalize.js";

export const ANALYSIS_LIMITS = { max_provider_observations: 16 } as const;

const RECOGNIZED_MALICIOUS_CATEGORIES = new Set([
  "malware",
  "social_engineering",
  "unwanted_software",
  "potentially_harmful_application",
]);

function timestamp(value: string, field: string): number {
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed)) throw new TypeError(`${field} must be a timestamp`);
  return parsed;
}

function freshnessAt(observedAt: string, expiresAt: string | null, evaluatedAt: string) {
  timestamp(observedAt, "observed_at");
  const evaluated = timestamp(evaluatedAt, "evaluated_at");
  if (expiresAt === null) return "unknown" as const;
  return timestamp(expiresAt, "expires_at") <= evaluated ? "stale" as const : "fresh" as const;
}

interface AnalysisBase {
  scan_id: string;
  mode: ScanMode;
  analyzed_at: string;
}

export type AnalysisInput = AnalysisBase & (
  | {
      target: CanonicalCandidateTarget;
      provider_observations?: readonly ProviderObservation[];
    }
  | {
      target: null;
      unscannable_reason: UnscannableReason;
    }
);

function malformedObservation(
  target: string,
  analyzedAt: string,
  source: ProviderSource,
): ProviderObservation {
  return {
    provider: "google_safe_browsing",
    source,
    queried_target: target,
    observed_at: analyzedAt,
    expires_at: null,
    freshness: "unknown",
    state: "error",
    category: null,
    confidence: "low",
    reference: null,
    error: "malformed_response",
  };
}

function observationSource(value: unknown): ProviderSource {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return "fixture";
  return (value as { source?: unknown }).source === "live" ? "live" : "fixture";
}

function normalizedObservation(
  value: ProviderObservation,
  target: string,
  analyzedAt: string,
): ProviderObservation {
  const source = observationSource(value);
  let observation: ProviderObservation;
  try {
    observation = parseProviderObservation(value);
    const observed = timestamp(observation.observed_at, "observed_at");
    const analyzed = timestamp(analyzedAt, "analyzed_at");
    if (observation.queried_target !== target || observed > analyzed) {
      return malformedObservation(target, analyzedAt, source);
    }
    if (observation.expires_at !== null) {
      const expires = timestamp(observation.expires_at, "expires_at");
      if (expires < observed) return malformedObservation(target, analyzedAt, source);
    }
  } catch {
    return malformedObservation(target, analyzedAt, source);
  }

  const matchValid = observation.state !== "match" || (
    observation.error === null &&
    observation.category !== null &&
    RECOGNIZED_MALICIOUS_CATEGORIES.has(observation.category)
  );
  const noMatchValid = observation.state !== "no_match" || (
    observation.error === null && observation.category === null
  );
  const errorValid = observation.state !== "error" || (
    observation.error !== null && observation.error !== "not_configured" &&
    observation.category === null
  );
  const notConfiguredValid = observation.state !== "not_configured" || (
    observation.error === "not_configured" && observation.category === null
  );
  if (!matchValid || !noMatchValid || !errorValid || !notConfiguredValid) {
    return malformedObservation(target, analyzedAt, source);
  }

  const freshness = observation.state === "match" || observation.state === "no_match"
    ? freshnessAt(observation.observed_at, observation.expires_at, analyzedAt)
    : "unknown";
  return {
    ...observation,
    freshness,
    confidence: freshness === "fresh" ? "medium" : "low",
  };
}

function compareKey(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function observationKey(observation: ProviderObservation): string {
  return [
    observation.provider, observation.source, observation.queried_target, observation.observed_at,
    observation.expires_at ?? "", observation.freshness, observation.state,
    observation.category ?? "", observation.confidence,
    observation.reference ?? "", observation.error ?? "",
  ].join("\u0000");
}

function normalizeObservations(
  values: readonly ProviderObservation[],
  target: string,
  analyzedAt: string,
): ProviderObservation[] {
  if (values.length > ANALYSIS_LIMITS.max_provider_observations) {
    throw new RangeError("too many provider observations");
  }
  const unique = new Map<string, ProviderObservation>();
  for (const value of values) {
    const observation = normalizedObservation(value, target, analyzedAt);
    unique.set(observationKey(observation), observation);
  }
  return [...unique.values()].sort((left, right) =>
    compareKey(observationKey(left), observationKey(right))
  );
}

function providerEvidence(observation: ProviderObservation, index: number): Evidence {
  return {
    source: `${observation.source}:${observation.provider}`,
    target: observation.queried_target,
    category: observation.state === "match"
      ? (observation.category ?? "unrecognized_match")
      : "no_known_match",
    observed_at: observation.observed_at,
    freshness: observation.freshness,
    reference: observation.reference,
    provider_observation_index: index,
  };
}

function candidateEvidence(target: CanonicalCandidateTarget): Evidence[] {
  const evidence = target.occurrences.flatMap((occurrence) => {
    if (occurrence.misleading_text === null) return [];
    return [{
      source: `candidate:${occurrence.candidate.provenance.source}`,
      target: target.canonical_url,
      category: "misleading_url_like_text",
      observed_at: occurrence.candidate.provenance.extracted_at,
      freshness: "fresh" as const,
      reference: occurrence.candidate.provenance.document_url,
      provider_observation_index: null,
    }];
  });
  const unique = new Map(evidence.map((item) => [evidenceKey(item), item]));
  return [...unique.values()].sort((left, right) => compareKey(evidenceKey(left), evidenceKey(right)));
}

function evidenceKey(evidence: Evidence): string {
  return [evidence.source, evidence.target, evidence.category, evidence.observed_at,
    evidence.freshness, evidence.reference ?? "", evidence.provider_observation_index ?? ""].join("\u0000");
}

function buildResult(input: AnalysisInput): ScanResult {
  timestamp(input.analyzed_at, "analyzed_at");
  if (input.target === null) {
    return {
      kind: "unscannable",
      scan_id: input.scan_id,
      mode: input.mode,
      canonical_target: null,
      unscannable_reason: input.unscannable_reason,
      outcome: "unscannable",
      risk_label: "unknown",
      analysis_state: "unscannable",
      confidence: "low",
      supporting_evidence: [],
      contradicting_evidence: [],
      provider_observations: [],
      limitation_codes: ["confidence_basis"],
    };
  }

  const observations = normalizeObservations(
    input.provider_observations ?? [],
    input.target.canonical_url,
    input.analyzed_at,
  );
  const candidate = candidateEvidence(input.target);
  const currentMatches = observations.filter((item) => item.state === "match" && item.freshness === "fresh");
  const currentNoMatches = observations.filter((item) => item.state === "no_match" && item.freshness === "fresh");
  const staleResults = observations.filter((item) =>
    (item.state === "match" || item.state === "no_match") && item.freshness !== "fresh"
  );
  const errors = observations.filter((item) => item.state === "error" || item.state === "not_configured");

  let riskLabel: RiskLabel = "unknown";
  if (currentMatches.length > 0) riskLabel = "known_malicious";
  else if (candidate.length > 0) riskLabel = "suspicious";
  else if (currentNoMatches.length > 0) riskLabel = "no_known_match";

  let analysisState: AnalysisState;
  if (currentMatches.length > 0 && currentNoMatches.length > 0) analysisState = "conflicting";
  else if (currentMatches.length > 0 || currentNoMatches.length > 0) analysisState = "complete";
  else if (staleResults.length > 0) analysisState = "stale";
  else if (errors.length > 0) analysisState = "provider_error";
  else analysisState = "unknown";

  let confidence: Confidence = "low";
  const hasContradiction = riskLabel === "no_known_match"
    ? observations.some((item) => item.state === "match")
    : observations.some((item) => item.state === "no_match");
  if (analysisState !== "conflicting" && errors.length === 0 && !hasContradiction) {
    if (riskLabel === "known_malicious") confidence = candidate.length > 0 ? "high" : "medium";
    else if (riskLabel === "no_known_match") confidence = "medium";
  }

  const matchEvidence = observations
    .map(providerEvidence)
    .filter((_, index) => observations[index]?.state === "match");
  const noMatchEvidence = observations
    .map(providerEvidence)
    .filter((_, index) => observations[index]?.state === "no_match");
  const supporting = riskLabel === "no_known_match"
    ? noMatchEvidence
    : [...candidate, ...matchEvidence];
  const contradicting = riskLabel === "no_known_match"
    ? matchEvidence
    : noMatchEvidence;
  supporting.sort((left, right) => compareKey(evidenceKey(left), evidenceKey(right)));
  contradicting.sort((left, right) => compareKey(evidenceKey(left), evidenceKey(right)));
  const limitationCodes: LimitationCode[] = [];
  if (candidate.length) limitationCodes.push("misleading_display_text");
  if (currentNoMatches.length) limitationCodes.push("provider_no_match_scope");
  if (currentMatches.length) limitationCodes.push("provider_match_scope");
  if (staleResults.length) limitationCodes.push("stale_observation");
  if (errors.length) limitationCodes.push("provider_unavailable");
  if (!observations.length) limitationCodes.push("no_provider_observation");
  if (analysisState === "conflicting") limitationCodes.push("conflicting_observations");
  limitationCodes.push("confidence_basis");

  return {
    kind: "analyzed",
    scan_id: input.scan_id,
    mode: input.mode,
    canonical_target: input.target.canonical_url,
    unscannable_reason: null,
    outcome: outcomeFor(riskLabel, analysisState, confidence),
    risk_label: riskLabel,
    analysis_state: analysisState,
    confidence,
    supporting_evidence: supporting,
    contradicting_evidence: contradicting,
    provider_observations: observations,
    limitation_codes: limitationCodes,
  };
}

/** The sole deterministic owner of aggregate label, state, and confidence. */
export function aggregateAnalysis(input: AnalysisInput): ScanResult {
  return parseScanResult(buildResult(input));
}
