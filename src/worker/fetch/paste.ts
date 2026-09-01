import { aggregateAnalysis } from "../../shared/analysis.js";
import { collectLinkCandidates } from "../../shared/candidates.js";
import {
  canonicalizeUrl,
  type UnscannableReason,
} from "../../shared/canonicalize.js";
import type { ScanMode, ScanResult } from "../../shared/contracts.js";
import {
  HTML_EXTRACTION_LIMITS,
  extractHtmlLinkCandidates,
} from "../../shared/extract-html.js";
import {
  SAFE_FETCH_LIMITS,
  safeFetchHtml,
  type SafeFetchEvidence,
  type SafeFetchSeams,
} from "./safe-fetch.js";
import type { ProviderAdapter } from "../providers/types.js";

export const PASTE_LIMITS = {
  max_request_bytes: 205_000,
  max_results: 16,
} as const;

export type PasteRequest =
  | { mode: "url"; url: string }
  | { mode: "html"; html: string; base_url: string };

export interface PasteReceipt {
  mode: ScanMode;
  scan_ids: string[];
  accepted_targets: number;
  rejected_candidates: number;
  truncated: boolean;
  unscannable_reason: UnscannableReason | null;
  fetch_evidence: SafeFetchEvidence | null;
}

export interface PasteDependencies {
  store(result: ScanResult): Promise<string>;
  provider?: ProviderAdapter;
  fetch_seams?: SafeFetchSeams;
  now?: () => Date;
}

function exactKeys(value: Record<string, unknown>, expected: string[]): boolean {
  const keys = Object.keys(value).sort();
  return keys.length === expected.length && keys.every((key, index) => key === expected[index]);
}

export function parsePasteRequest(value: unknown): PasteRequest | null {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return null;
  const data = value as Record<string, unknown>;
  if (data.mode === "url") {
    return exactKeys(data, ["mode", "url"]) && typeof data.url === "string"
      ? { mode: "url", url: data.url }
      : null;
  }
  if (data.mode === "html") {
    return exactKeys(data, ["base_url", "html", "mode"]) &&
      typeof data.html === "string" && typeof data.base_url === "string"
      ? { mode: "html", html: data.html, base_url: data.base_url }
      : null;
  }
  return null;
}

function unavailable(mode: ScanMode, reason: UnscannableReason, analyzedAt: string): ScanResult {
  return aggregateAnalysis({
    scan_id: "pending",
    mode,
    analyzed_at: analyzedAt,
    target: null,
    unscannable_reason: reason,
  });
}

async function storeAll(
  results: ScanResult[],
  dependencies: PasteDependencies,
): Promise<string[]> {
  const ids: string[] = [];
  for (const result of results) ids.push(await dependencies.store(result));
  return ids;
}

export async function executePasteScan(
  request: PasteRequest,
  dependencies: PasteDependencies,
): Promise<PasteReceipt> {
  const analyzedAt = (dependencies.now ?? (() => new Date()))().toISOString();
  const mode: ScanMode = request.mode === "url" ? "paste_url" : "paste_html";
  let html: string;
  let baseUrl: string;
  let fetchEvidence: SafeFetchEvidence | null = null;

  if (request.mode === "url") {
    const fetched = await safeFetchHtml(request.url, dependencies.fetch_seams);
    fetchEvidence = fetched.evidence;
    if (!fetched.ok) {
      return {
        mode,
        scan_ids: await storeAll([unavailable(mode, fetched.reason, analyzedAt)], dependencies),
        accepted_targets: 0,
        rejected_candidates: 0,
        truncated: false,
        unscannable_reason: fetched.reason,
        fetch_evidence: fetchEvidence,
      };
    }
    html = fetched.html;
    baseUrl = fetched.evidence.final_url;
  } else {
    if (request.html.length > HTML_EXTRACTION_LIMITS.max_input_chars) {
      const reason = "input_too_large" as const;
      return {
        mode,
        scan_ids: await storeAll([unavailable(mode, reason, analyzedAt)], dependencies),
        accepted_targets: 0,
        rejected_candidates: 0,
        truncated: false,
        unscannable_reason: reason,
        fetch_evidence: null,
      };
    }
    const base = request.base_url.length <= SAFE_FETCH_LIMITS.max_url_chars
      ? canonicalizeUrl(request.base_url) : null;
    if (base === null || !base.ok || base.target.canonical_url.length > SAFE_FETCH_LIMITS.max_url_chars) {
      const reason: UnscannableReason = base === null || base.ok ? "url_too_long" : base.reason;
      return {
        mode,
        scan_ids: await storeAll([unavailable(mode, reason, analyzedAt)], dependencies),
        accepted_targets: 0,
        rejected_candidates: 0,
        truncated: false,
        unscannable_reason: reason,
        fetch_evidence: null,
      };
    }
    html = request.html;
    baseUrl = base.target.canonical_url;
  }

  let candidates = extractHtmlLinkCandidates(html, {
    base_url: baseUrl,
    document_url: baseUrl,
    extracted_at: analyzedAt,
  });
  if (mode === "paste_url") {
    candidates = candidates.map((candidate) => ({
      ...candidate,
      provenance: { ...candidate.provenance, source: "paste_url" },
    }));
  }
  const collection = collectLinkCandidates(candidates);
  const targets = collection.targets.filter(
    (target) => target.canonical_url.length <= SAFE_FETCH_LIMITS.max_url_chars,
  );
  const oversizedTargets = collection.targets.length - targets.length;
  const rejectionReasons: UnscannableReason[] = [
    ...collection.rejected.map(({ reason }) => reason),
    ...Array<UnscannableReason>(oversizedTargets).fill("url_too_long"),
  ];
  let onlyReason: UnscannableReason | null = targets.length === 0 && rejectionReasons.length === 1
    ? (rejectionReasons[0] ?? null) : null;
  const retainedTargets = targets.slice(0, PASTE_LIMITS.max_results);
  const results = await Promise.all(retainedTargets.map(async (target): Promise<ScanResult> => {
    const providerObservations = dependencies.provider === undefined ? undefined : [
      await dependencies.provider.observe({
        canonical_target: target.canonical_url,
        requested_at: analyzedAt,
      }),
    ];
    return aggregateAnalysis({
      scan_id: "pending",
      mode,
      analyzed_at: analyzedAt,
      target,
      ...(providerObservations === undefined ? {} : {
        provider_observations: providerObservations,
      }),
    });
  }));
  results.push(...rejectionReasons.map((reason) => unavailable(mode, reason, analyzedAt)));
  if (results.length === 0) {
    onlyReason = "no_candidates";
    results.push(unavailable(mode, onlyReason, analyzedAt));
  }
  const truncated = targets.length + rejectionReasons.length > PASTE_LIMITS.max_results;
  const retained = results.slice(0, PASTE_LIMITS.max_results);
  if (truncated) {
    for (const result of retained) result.limitations.push(
      `Only the first ${PASTE_LIMITS.max_results} bounded results were retained.`,
    );
  }
  return {
    mode,
    scan_ids: await storeAll(retained, dependencies),
    accepted_targets: targets.length,
    rejected_candidates: rejectionReasons.length,
    truncated,
    unscannable_reason: onlyReason,
    fetch_evidence: fetchEvidence,
  };
}
