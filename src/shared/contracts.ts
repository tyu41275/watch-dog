export const RISK_LABELS = [
  "known_malicious",
  "suspicious",
  "no_known_match",
  "unknown",
] as const;

export const ANALYSIS_STATES = [
  "complete",
  "unknown",
  "unscannable",
  "provider_error",
  "stale",
  "conflicting",
] as const;

export const CONFIDENCE_LEVELS = ["high", "medium", "low"] as const;
export const SCAN_MODES = ["paste_url", "paste_html", "live_page"] as const;
export const FRESHNESS_STATES = ["fresh", "stale", "unknown"] as const;
export const PROVIDER_IDS = ["google_safe_browsing"] as const;
export const PROVIDER_SOURCES = ["live", "fixture"] as const;
export const PROVIDER_STATES = [
  "match",
  "no_match",
  "error",
  "not_configured",
] as const;
export const PROVIDER_ERROR_CODES = [
  "timeout",
  "quota",
  "unavailable",
  "malformed_response",
  "not_configured",
] as const;
export const OUTCOME_PRESENTATION = {
  unscannable: ["unknown", "unscannable", "low"], unknown: ["unknown", "unknown", "low"], unknown_stale: ["unknown", "stale", "low"],
  unknown_provider_error: ["unknown", "provider_error", "low"], suspicious: ["suspicious", "unknown", "low"], suspicious_stale: ["suspicious", "stale", "low"],
  suspicious_provider_error: ["suspicious", "provider_error", "low"], suspicious_complete: ["suspicious", "complete", "low"],
  known_malicious_high: ["known_malicious", "complete", "high"], known_malicious_medium: ["known_malicious", "complete", "medium"],
  known_malicious_low: ["known_malicious", "complete", "low"], known_malicious_conflicting: ["known_malicious", "conflicting", "low"],
  no_known_match_medium: ["no_known_match", "complete", "medium"], no_known_match_low: ["no_known_match", "complete", "low"],
} as const;
export const LIMITATION_CODES = ["confidence_basis", "misleading_display_text", "provider_no_match_scope",
  "provider_match_scope", "stale_observation", "provider_unavailable", "no_provider_observation", "conflicting_observations", "results_truncated"] as const;
export const UNSCANNABLE_REASONS = [
  "empty_input", "missing_base_url", "invalid_url", "unsupported_scheme", "credentials_not_allowed", "disallowed_port", "url_too_long", "unsafe_address",
  "dns_failure", "mixed_address", "redirect_missing_location", "redirect_loop", "redirect_limit", "timeout", "response_too_large", "unsupported_content_type",
  "unsupported_content_encoding", "fetch_failed", "invalid_response", "input_too_large", "no_candidates",
] as const;

export type RiskLabel = (typeof RISK_LABELS)[number];
export type AnalysisState = (typeof ANALYSIS_STATES)[number];
export type Confidence = (typeof CONFIDENCE_LEVELS)[number];
export type ScanMode = (typeof SCAN_MODES)[number];
export type Freshness = (typeof FRESHNESS_STATES)[number];
export type ProviderId = (typeof PROVIDER_IDS)[number];
export type ProviderSource = (typeof PROVIDER_SOURCES)[number];
export type ProviderState = (typeof PROVIDER_STATES)[number];
export type ProviderErrorCode = (typeof PROVIDER_ERROR_CODES)[number];
export type OutcomeCode = keyof typeof OUTCOME_PRESENTATION;
export type LimitationCode = (typeof LIMITATION_CODES)[number];

export interface ExtractionProvenance {
  source: ScanMode;
  document_url: string;
  occurrence_index: number;
  extracted_at: string;
}

export interface ExtractedLinkCandidate {
  raw_href: string;
  anchor_text: string;
  base_url: string;
  provenance: ExtractionProvenance;
}

export interface ProviderObservation {
  provider: ProviderId;
  source: ProviderSource;
  queried_target: string;
  observed_at: string;
  expires_at: string | null;
  freshness: Freshness;
  state: ProviderState;
  category: string | null;
  confidence: Confidence;
  reference: string | null;
  error: ProviderErrorCode | null;
}

export interface Evidence {
  source: string;
  target: string;
  category: string;
  observed_at: string;
  freshness: Freshness;
  reference: string | null;
  provider_observation_index: number | null;
}

export interface ScanResult {
  kind: "analyzed" | "unscannable";
  scan_id: string;
  mode: ScanMode;
  canonical_target: string | null;
  unscannable_reason: (typeof UNSCANNABLE_REASONS)[number] | null;
  outcome: OutcomeCode;
  risk_label: RiskLabel;
  analysis_state: AnalysisState;
  confidence: Confidence;
  supporting_evidence: Evidence[];
  contradicting_evidence: Evidence[];
  provider_observations: ProviderObservation[];
  limitation_codes: LimitationCode[];
}

type RecordValue = Record<string, unknown>;

function record(value: unknown, path: string): RecordValue {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new TypeError(`${path} must be an object`);
  }
  return value as RecordValue;
}

function exactKeys(value: RecordValue, keys: readonly string[], path: string): void {
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, i) => key !== expected[i])) {
    throw new TypeError(`${path} has unknown or missing fields`);
  }
}

function literal<T extends string>(
  value: unknown,
  allowed: readonly T[],
  path: string,
): T {
  if (typeof value !== "string" || !allowed.includes(value as T)) {
    throw new TypeError(`${path} has an invalid literal`);
  }
  return value as T;
}

function string(value: unknown, path: string): string {
  if (typeof value !== "string") throw new TypeError(`${path} must be a string`);
  return value;
}

function nullableString(value: unknown, path: string): string | null {
  return value === null ? null : string(value, path);
}

function integer(value: unknown, path: string): number {
  if (!Number.isSafeInteger(value) || (value as number) < 0) {
    throw new TypeError(`${path} must be a non-negative integer`);
  }
  return value as number;
}

function array<T>(value: unknown, path: string, parse: (item: unknown, path: string) => T): T[] {
  if (!Array.isArray(value)) throw new TypeError(`${path} must be an array`);
  return value.map((item, index) => parse(item, `${path}[${index}]`));
}

function parseProvenance(value: unknown, path: string): ExtractionProvenance {
  const data = record(value, path);
  exactKeys(data, ["source", "document_url", "occurrence_index", "extracted_at"], path);
  return {
    source: literal(data.source, SCAN_MODES, `${path}.source`),
    document_url: string(data.document_url, `${path}.document_url`),
    occurrence_index: integer(data.occurrence_index, `${path}.occurrence_index`),
    extracted_at: string(data.extracted_at, `${path}.extracted_at`),
  };
}

export function parseExtractedLinkCandidate(value: unknown): ExtractedLinkCandidate {
  const data = record(value, "candidate");
  exactKeys(data, ["raw_href", "anchor_text", "base_url", "provenance"], "candidate");
  return {
    raw_href: string(data.raw_href, "candidate.raw_href"),
    anchor_text: string(data.anchor_text, "candidate.anchor_text"),
    base_url: string(data.base_url, "candidate.base_url"),
    provenance: parseProvenance(data.provenance, "candidate.provenance"),
  };
}

export function parseProviderObservation(value: unknown): ProviderObservation {
  const path = "provider_observation";
  const data = record(value, path);
  exactKeys(data, [
    "provider", "source", "queried_target", "observed_at", "expires_at", "freshness",
    "state", "category", "confidence", "reference", "error",
  ], path);
  const result = {
    provider: literal(data.provider, PROVIDER_IDS, `${path}.provider`),
    source: literal(data.source, PROVIDER_SOURCES, `${path}.source`),
    queried_target: string(data.queried_target, `${path}.queried_target`),
    observed_at: string(data.observed_at, `${path}.observed_at`),
    expires_at: nullableString(data.expires_at, `${path}.expires_at`),
    freshness: literal(data.freshness, FRESHNESS_STATES, `${path}.freshness`),
    state: literal(data.state, PROVIDER_STATES, `${path}.state`),
    category: nullableString(data.category, `${path}.category`),
    confidence: literal(data.confidence, CONFIDENCE_LEVELS, `${path}.confidence`),
    reference: nullableString(data.reference, `${path}.reference`),
    error: data.error === null
      ? null
      : literal(data.error, PROVIDER_ERROR_CODES, `${path}.error`),
  };
  const categoryOk = result.state === "match" ? ["malware", "social_engineering",
    "unwanted_software", "potentially_harmful_application"].includes(result.category ?? "") :
    result.category === null;
  const errorOk = result.state === "error" ? result.error !== null && result.error !== "not_configured" :
    result.state === "not_configured" ? result.error === "not_configured" : result.error === null;
  if (!categoryOk || !errorOk || (result.source === "live" && result.state === "match" &&
    result.reference !== "https://transparencyreport.google.com/safe-browsing/search")) {
    throw new TypeError(`${path} has an impossible state relation`);
  }
  return result;
}

function parseEvidence(value: unknown, path: string): Evidence {
  const data = record(value, path);
  exactKeys(data, ["source", "target", "category", "observed_at", "freshness", "reference",
    "provider_observation_index"], path);
  return {
    source: string(data.source, `${path}.source`),
    target: string(data.target, `${path}.target`),
    category: string(data.category, `${path}.category`),
    observed_at: string(data.observed_at, `${path}.observed_at`),
    freshness: literal(data.freshness, FRESHNESS_STATES, `${path}.freshness`),
    reference: nullableString(data.reference, `${path}.reference`),
    provider_observation_index: data.provider_observation_index === null ? null :
      integer(data.provider_observation_index, `${path}.provider_observation_index`),
  };
}

export function outcomeFor(risk: RiskLabel, state: AnalysisState, confidence: Confidence): OutcomeCode {
  const found = Object.entries(OUTCOME_PRESENTATION).find(([, tuple]) =>
    tuple[0] === risk && tuple[1] === state && tuple[2] === confidence)?.[0];
  if (found === undefined) throw new TypeError("result tuple has no finite outcome");
  return found as OutcomeCode;
}

export function parseScanResult(value: unknown): ScanResult {
  const path = "scan_result";
  const data = record(value, path);
  exactKeys(data, [
    "kind", "scan_id", "mode", "canonical_target", "unscannable_reason", "outcome",
    "risk_label", "analysis_state", "confidence", "supporting_evidence", "contradicting_evidence",
    "provider_observations", "limitation_codes",
  ], path);
  const result: ScanResult = {
    kind: literal(data.kind, ["analyzed", "unscannable"], `${path}.kind`),
    scan_id: string(data.scan_id, `${path}.scan_id`),
    mode: literal(data.mode, SCAN_MODES, `${path}.mode`),
    canonical_target: nullableString(data.canonical_target, `${path}.canonical_target`),
    unscannable_reason: data.unscannable_reason === null ? null :
      literal(data.unscannable_reason, UNSCANNABLE_REASONS, `${path}.unscannable_reason`),
    outcome: literal(data.outcome, Object.keys(OUTCOME_PRESENTATION) as OutcomeCode[], `${path}.outcome`),
    risk_label: literal(data.risk_label, RISK_LABELS, `${path}.risk_label`),
    analysis_state: literal(data.analysis_state, ANALYSIS_STATES, `${path}.analysis_state`),
    confidence: literal(data.confidence, CONFIDENCE_LEVELS, `${path}.confidence`),
    supporting_evidence: array(data.supporting_evidence, `${path}.supporting_evidence`, parseEvidence),
    contradicting_evidence: array(data.contradicting_evidence, `${path}.contradicting_evidence`, parseEvidence),
    provider_observations: array(data.provider_observations, `${path}.provider_observations`, parseProviderObservation),
    limitation_codes: array(data.limitation_codes, `${path}.limitation_codes`, (item, itemPath) =>
      literal(item, LIMITATION_CODES, itemPath)),
  };
  if (result.outcome !== outcomeFor(result.risk_label, result.analysis_state, result.confidence) ||
    (result.kind === "unscannable") !== (result.canonical_target === null &&
      result.unscannable_reason !== null && result.analysis_state === "unscannable") ||
    (result.kind === "analyzed" && result.unscannable_reason !== null) ||
    new Set(result.limitation_codes).size !== result.limitation_codes.length) {
    throw new TypeError(`${path} has an impossible variant`);
  }
  const evidence = [...result.supporting_evidence, ...result.contradicting_evidence];
  if (result.kind === "unscannable" && (evidence.length || result.provider_observations.length) ||
    evidence.some((item) => item.target !== result.canonical_target ||
      (item.source.startsWith("candidate:") ? item.provider_observation_index !== null ||
        item.source !== `candidate:${result.mode}` : item.provider_observation_index === null ||
        item.provider_observation_index >= result.provider_observations.length))) {
    throw new TypeError(`${path} has an impossible evidence relation`);
  }
  return result;
}
