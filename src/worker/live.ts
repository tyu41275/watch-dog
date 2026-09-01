import { aggregateAnalysis } from "../shared/analysis.js";
import { collectLinkCandidates } from "../shared/candidates.js";
import type { UnscannableReason } from "../shared/canonicalize.js";
import {
  parseExtractedLinkCandidate,
  type ExtractedLinkCandidate,
  type ScanResult,
} from "../shared/contracts.js";

export const LIVE_LIMITS = {
  max_request_bytes: 256_000,
  max_candidates: 32,
  max_results: 16,
  max_href_chars: 2_048,
  max_anchor_text_chars: 512,
  max_url_chars: 2_048,
} as const;

export interface LiveRequest {
  document_url: string;
  observed_at: string;
  candidates: ExtractedLinkCandidate[];
  extraction_rejections: Array<{
    occurrence_index: number;
    reason: "url_too_long";
  }>;
}

export interface LiveReceipt {
  mode: "live_page";
  scan_ids: string[];
  observed_candidates: number;
  accepted_targets: number;
  rejected_candidates: number;
  truncated: boolean;
  page_evidence_trust: "untrusted";
  targets: Array<{
    canonical_url: string;
    occurrence_indices: number[];
    anchor_text_variants: string[];
  }>;
  rejections: Array<{ occurrence_index: number; reason: UnscannableReason }>;
}

export interface LiveDependencies {
  store(result: ScanResult): Promise<string>;
  now?: () => Date;
}

function exactKeys(value: Record<string, unknown>, expected: string[]): boolean {
  const keys = Object.keys(value).sort();
  return keys.length === expected.length && keys.every((key, index) => key === expected[index]);
}

function validTimestamp(value: string): boolean {
  return Number.isFinite(Date.parse(value)) && new Date(value).toISOString() === value;
}

function fixedReferenceUrl(value: string, expectedOrigin: string): boolean {
  if (value.length > LIVE_LIMITS.max_url_chars) return false;
  try {
    const url = new URL(value);
    return url.origin === expectedOrigin && url.pathname === "/reference" &&
      url.search === "" && url.username === "" && url.password === "";
  } catch {
    return false;
  }
}

export function parseLiveRequest(
  value: unknown,
  expectedOrigin: string,
  nowMs = Date.now(),
): LiveRequest | null {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return null;
  const data = value as Record<string, unknown>;
  if (!exactKeys(data, ["candidates", "document_url", "extraction_rejections", "observed_at"])) {
    return null;
  }
  if (typeof data.document_url !== "string" || typeof data.observed_at !== "string") return null;
  if (!Array.isArray(data.candidates) || !Array.isArray(data.extraction_rejections)) return null;
  if (data.candidates.length + data.extraction_rejections.length > LIVE_LIMITS.max_candidates) return null;
  if (!fixedReferenceUrl(data.document_url, expectedOrigin) || !validTimestamp(data.observed_at)) return null;
  const observedMs = Date.parse(data.observed_at);
  if (observedMs < nowMs - 5 * 60_000 || observedMs > nowMs + 60_000) return null;

  try {
    const candidates = data.candidates.map((value) => {
      const candidate = parseExtractedLinkCandidate(value);
      const base = new URL(candidate.base_url);
      if (
        candidate.provenance.source !== "live_page" ||
        candidate.provenance.document_url !== data.document_url ||
        candidate.provenance.extracted_at !== data.observed_at ||
        !fixedReferenceUrl(candidate.base_url, expectedOrigin) ||
        candidate.base_url.length > LIVE_LIMITS.max_url_chars ||
        candidate.raw_href.length > LIVE_LIMITS.max_href_chars ||
        candidate.anchor_text.length > LIVE_LIMITS.max_anchor_text_chars
      ) throw new TypeError("invalid live candidate");
      return candidate;
    });
    const extractionRejections = data.extraction_rejections.map((value) => {
      if (typeof value !== "object" || value === null || Array.isArray(value)) {
        throw new TypeError("invalid extraction rejection");
      }
      const rejection = value as Record<string, unknown>;
      if (
        !exactKeys(rejection, ["occurrence_index", "reason"]) ||
        !Number.isSafeInteger(rejection.occurrence_index) ||
        (rejection.occurrence_index as number) < 0 ||
        rejection.reason !== "url_too_long"
      ) throw new TypeError("invalid extraction rejection");
      return {
        occurrence_index: rejection.occurrence_index as number,
        reason: "url_too_long" as const,
      };
    });
    const indices = [
      ...candidates.map(({ provenance }) => provenance.occurrence_index),
      ...extractionRejections.map(({ occurrence_index }) => occurrence_index),
    ].sort((left, right) => left - right);
    if (indices.some((value, index) => value !== index)) {
      throw new TypeError("live occurrence indices must be complete and unique");
    }
    return {
      document_url: data.document_url,
      observed_at: data.observed_at,
      candidates,
      extraction_rejections: extractionRejections,
    };
  } catch {
    return null;
  }
}

function unavailable(reason: UnscannableReason, analyzedAt: string): ScanResult {
  return aggregateAnalysis({
    scan_id: "pending",
    mode: "live_page",
    analyzed_at: analyzedAt,
    target: null,
    unscannable_reason: reason,
  });
}

export async function executeLiveScan(
  request: LiveRequest,
  dependencies: LiveDependencies,
): Promise<LiveReceipt> {
  const serverTime = (dependencies.now ?? (() => new Date()))();
  const analyzedAt = new Date(Math.max(serverTime.getTime(), Date.parse(request.observed_at)))
    .toISOString();
  const collection = collectLinkCandidates(request.candidates);
  const targets = collection.targets.filter(
    ({ canonical_url }) => canonical_url.length <= LIVE_LIMITS.max_url_chars,
  );
  const rejections: Array<{ occurrence_index: number; reason: UnscannableReason }> = [
    ...request.extraction_rejections,
    ...collection.rejected.map(({ candidate, reason }) => ({
      occurrence_index: candidate.provenance.occurrence_index,
      reason,
    })),
    ...collection.targets
      .filter(({ canonical_url }) => canonical_url.length > LIVE_LIMITS.max_url_chars)
      .flatMap(({ occurrences }) => occurrences.map(({ candidate }) => ({
        occurrence_index: candidate.provenance.occurrence_index,
        reason: "url_too_long" as const,
      }))),
  ].sort((left, right) => left.occurrence_index - right.occurrence_index);
  const results: ScanResult[] = targets.map((target) => aggregateAnalysis({
    scan_id: "pending",
    mode: "live_page",
    analyzed_at: analyzedAt,
    target,
  }));
  results.push(...rejections.map(({ reason }) => unavailable(reason, analyzedAt)));
  if (results.length === 0) results.push(unavailable("no_candidates", analyzedAt));
  const truncated = results.length > LIVE_LIMITS.max_results;
  const retained = results.slice(0, LIVE_LIMITS.max_results);
  if (truncated) {
    for (const result of retained) result.limitations.push(
      `Only the first ${LIVE_LIMITS.max_results} bounded results were retained.`,
    );
  }
  const scanIds: string[] = [];
  for (const result of retained) scanIds.push(await dependencies.store(result));
  return {
    mode: "live_page",
    scan_ids: scanIds,
    observed_candidates: request.candidates.length + request.extraction_rejections.length,
    accepted_targets: targets.length,
    rejected_candidates: rejections.length,
    truncated,
    page_evidence_trust: "untrusted",
    targets: targets.slice(0, LIVE_LIMITS.max_results).map((target) => ({
      canonical_url: target.canonical_url,
      occurrence_indices: target.occurrences.map(({ candidate }) =>
        candidate.provenance.occurrence_index),
      anchor_text_variants: target.anchor_text_variants,
    })),
    rejections: rejections.slice(0, LIVE_LIMITS.max_results),
  };
}
