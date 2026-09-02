import {
  parseExtractedLinkCandidate,
  type ExtractedLinkCandidate,
  type ScanResult,
} from "../shared/contracts.js";
import {
  createScanMachine,
  reduceScanMachine,
  scanJournalEntry,
  type ExtractAtom,
  type ProviderPrimitive,
  type ScanInput,
  type ScanJournalEntry,
} from "../shared/scan-machine.js";
import type { ProviderAdapter } from "./providers/types.js";
import type { UnscannableReason } from "../shared/canonicalize.js";

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
  mode: "live_page"; scan_ids: string[]; observed_candidates: number;
  accepted_targets: number; rejected_candidates: number; truncated: boolean;
  page_evidence_trust: "untrusted";
  targets: Array<{ canonical_url: string; occurrence_indices: number[]; anchor_text_variants: string[] }>;
  rejections: Array<{ occurrence_index: number; reason: UnscannableReason }>;
}
export interface LiveOperation { version: 1; input: ScanInput; journal: readonly ScanJournalEntry[] }

export interface LiveDependencies {
  store(result: ScanResult): Promise<string>;
  provider?: ProviderAdapter;
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

function primitive(observation: Awaited<ReturnType<ProviderAdapter["observe"]>>): ProviderPrimitive {
  return { provider: observation.provider, source: observation.source,
    queried_target: observation.queried_target, observed_at: observation.observed_at,
    expires_at: observation.expires_at, state: observation.state, category: observation.category,
    reference: observation.reference, error: observation.error };
}

const freeze = <T>(value: T): T => { if (typeof value === "object" && value !== null) { for (const child of Object.values(value)) freeze(child); Object.freeze(value); } return value; };

export async function executeLiveOperation(
  request: LiveRequest,
  dependencies: LiveDependencies,
): Promise<LiveOperation> {
  const serverTime = (dependencies.now ?? (() => new Date()))();
  const analyzedAt = new Date(Math.max(serverTime.getTime(), Date.parse(request.observed_at)))
    .toISOString();
  const input: ScanInput = { version: 1, kind: "live_page", analyzed_at: analyzedAt,
    base_url: request.document_url, document_url: request.document_url };
  let machine = createScanMachine(input);
  const atoms = [
    ...request.candidates.map((candidate) => ({ index: candidate.provenance.occurrence_index,
      atom: { kind: "ANCHOR", href: candidate.raw_href, href_overflow: false,
        text: candidate.anchor_text, text_overflow: false } as ExtractAtom })),
    ...request.extraction_rejections.map((rejection) => ({ index: rejection.occurrence_index,
      atom: { kind: "ANCHOR", href: null, href_overflow: true, text: "",
        text_overflow: false } as ExtractAtom })),
  ].sort((left, right) => left.index - right.index).map(({ atom }) => atom);
  const journal: ScanJournalEntry[] = [];
  while (machine.pending?.kind !== "ALLOCATE_IDS") {
    const effect = machine.pending;
    if (effect === null) throw new TypeError("live scan ended before allocation");
    const fact = effect.kind === "EXTRACT_HTML"
      ? (effect.body.kind !== "rendered_anchors" ? (() => { throw new TypeError("invalid live effect"); })()
        : { kind: "EXTRACTED" as const, effect_id: effect.id, atoms })
      : { kind: "PROVIDER_OBSERVED" as const, effect_id: effect.id,
          ...await (async () => {
            const requests = effect.batch ?? [effect];
            const batch = await Promise.all(requests.map(async (request) => dependencies.provider === undefined
              ? { provider: "google_safe_browsing", source: "live", queried_target: request.canonical_target,
                  observed_at: request.requested_at, expires_at: null, state: "not_configured",
                  category: null, reference: null, error: "not_configured" } as const
              : primitive(await dependencies.provider.observe({ canonical_target: request.canonical_target,
                  requested_at: request.requested_at }))));
            return effect.batch === undefined ? { observation: batch[0]! }
              : { observation: batch[0]!, batch };
          })() };
    const entry = scanJournalEntry(effect, fact);
    journal.push(entry);
    machine = reduceScanMachine(machine, entry.fact);
  }
  return freeze(structuredClone({ version: 1 as const, input, journal }));
}

export async function executeLiveScan(
  request: LiveRequest,
  dependencies: LiveDependencies,
): Promise<LiveReceipt> {
  const operation = await executeLiveOperation(request, dependencies);
  let machine = createScanMachine(operation.input);
  for (const entry of operation.journal) machine = reduceScanMachine(machine, entry.fact);
  const effect = machine.pending;
  if (effect?.kind !== "ALLOCATE_IDS") throw new TypeError("live prefix is incomplete");
  const provisional = Array.from({ length: effect.count }, (_, index) =>
    (index + 1).toString(16).padStart(32, "0"));
  const preview = reduceScanMachine(machine,
    { kind: "IDS_ALLOCATED", effect_id: effect.id, ids: provisional }).exchange;
  if (preview === null) throw new TypeError("live preview is incomplete");
  const scanIds: string[] = [];
  for (const entry of preview.entries) scanIds.push(await dependencies.store(entry.result));
  if (new Set(scanIds).size !== scanIds.length ||
    scanIds.some((id) => !/^[a-f0-9]{32}$/u.test(id))) throw new TypeError("invalid allocated ID");
  let receiptId: string;
  do receiptId = crypto.randomUUID().replaceAll("-", "").toLowerCase();
  while (scanIds.includes(receiptId));
  const final = reduceScanMachine(machine,
    { kind: "IDS_ALLOCATED", effect_id: effect.id, ids: [receiptId, ...scanIds] }).exchange;
  if (final === null) throw new TypeError("live exchange is incomplete");
  const receipt = final.receipt;
  return {
    mode: "live_page", scan_ids: [...receipt.scan_ids],
    observed_candidates: receipt.occurrence_count.count,
    accepted_targets: receipt.accepted_targets, rejected_candidates: receipt.rejected_candidates,
    truncated: receipt.truncated, page_evidence_trust: "untrusted",
    targets: receipt.targets.map((target) => ({ canonical_url: target.canonical_url,
      occurrence_indices: target.occurrences.map(({ occurrence_index }) => occurrence_index),
      anchor_text_variants: [...target.anchor_text_variants] })),
    rejections: receipt.rejections.map(({ occurrence_index, reason }) => ({ occurrence_index, reason })),
  };
}
