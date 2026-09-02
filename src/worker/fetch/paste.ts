import { extractHtmlScanAtoms } from "../../shared/extract-html.js";
import { createScanMachine, reduceScanMachine, scanJournalEntry, type ProviderPrimitive, type ScanInput, type ScanJournalEntry } from "../../shared/scan-machine.js";
import type { JournalEntry } from "./fetch-machine.js";
import { SAFE_FETCH_LIMITS, safeFetchHtml, type SafeFetchSeams } from "./safe-fetch.js";
import type { ProviderAdapter } from "../providers/types.js";

export const PASTE_LIMITS = {
  max_request_bytes: 205_000,
  max_results: 16,
} as const;

export type PasteRequest =
  | { mode: "url"; url: string }
  | { mode: "html"; html: string; base_url: string };

export interface PasteOperation { version: 1; input: ScanInput; journal: readonly ScanJournalEntry[] }
export interface PasteDependencies {
  provider?: ProviderAdapter;
  fetch_seams?: SafeFetchSeams;
  now?: () => Date;
  signal?: AbortSignal;
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

function cancelled(signal: AbortSignal | undefined): void {
  if (signal?.aborted) throw signal.reason instanceof Error ? signal.reason : new DOMException("scan cancelled", "AbortError");
}

function primitive(observation: Awaited<ReturnType<ProviderAdapter["observe"]>>): ProviderPrimitive {
  return { provider: observation.provider, source: observation.source,
    queried_target: observation.queried_target, observed_at: observation.observed_at,
    expires_at: observation.expires_at, state: observation.state, category: observation.category,
    reference: observation.reference, error: observation.error };
}
const freeze = <T>(value: T): T => { if (typeof value === "object" && value !== null) { for (const child of Object.values(value)) freeze(child); Object.freeze(value); } return value; };

export async function executePasteScan(
  request: PasteRequest,
  dependencies: PasteDependencies = {},
): Promise<PasteOperation> {
  cancelled(dependencies.signal); const analyzedAt = (dependencies.now ?? (() => new Date()))().toISOString();
  let input: ScanInput, fetchedHtml: string | undefined;
  if (request.mode === "html") {
    input = { version: 1, kind: "paste_html", analyzed_at: analyzedAt,
      base_url: request.base_url, html: request.html };
  } else {
    const fetchJournal: JournalEntry[] = [];
    const seams = dependencies.fetch_seams ?? {};
    const clock = seams.now ?? Date.now;
    let started: number | undefined;
    const fetched = await safeFetchHtml(request.url, { ...seams,
      now: () => { const value = clock(); started ??= value; return value; },
      record: (entry) => { fetchJournal.push(entry); seams.record?.(entry); },
    });
    cancelled(dependencies.signal);
    if (started === undefined) throw new TypeError("fetch did not start");
    input = { version: 1, kind: "paste_url", analyzed_at: analyzedAt, request_url: request.url,
      fetch: { started, limits: { max_url_chars: SAFE_FETCH_LIMITS.max_url_chars,
        max_redirects: SAFE_FETCH_LIMITS.max_redirects,
        max_response_bytes: SAFE_FETCH_LIMITS.max_response_bytes,
        operation_ms: seams.operation_ms ?? SAFE_FETCH_LIMITS.per_operation_ms,
        total_ms: seams.total_ms ?? SAFE_FETCH_LIMITS.total_ms }, journal: fetchJournal } };
    if (fetched.ok) fetchedHtml = fetched.html;
  }

  let machine = createScanMachine(input);
  const journal: ScanJournalEntry[] = [];
  while (machine.pending?.kind !== "ALLOCATE_IDS") {
    cancelled(dependencies.signal);
    const effect = machine.pending;
    if (effect === null) throw new TypeError("scan ended before allocation");
    let fact;
    if (effect.kind === "EXTRACT_HTML") {
      const html = effect.body.kind === "inline_html" ? effect.body.html : fetchedHtml;
      if (html === undefined) throw new TypeError("fetch body binding mismatch");
      fact = { kind: "EXTRACTED" as const, effect_id: effect.id, atoms: extractHtmlScanAtoms(html) };
    } else {
      const observation = dependencies.provider === undefined
        ? { provider: "google_safe_browsing", source: "live", queried_target: effect.canonical_target,
            observed_at: effect.requested_at, expires_at: null, state: "not_configured", category: null,
            reference: null, error: "not_configured" } as const
        : primitive(await dependencies.provider.observe({ canonical_target: effect.canonical_target,
            requested_at: effect.requested_at }));
      cancelled(dependencies.signal);
      fact = { kind: "PROVIDER_OBSERVED" as const, effect_id: effect.id, observation };
    }
    const entry = scanJournalEntry(effect, fact);
    journal.push(entry);
    machine = reduceScanMachine(machine, entry.fact);
  }
  cancelled(dependencies.signal);
  if (machine.phase !== "AWAIT_IDS" || machine.pending.count < 2) {
    throw new TypeError("scan prefix is not ready for allocation");
  }
  return freeze(structuredClone({ version: 1 as const, input, journal }));
}
