import { aggregateAnalysis } from "./analysis.js";
import { collectLinkCandidates, type CanonicalCandidateTarget } from "./candidates.js";
import { canonicalizeUrl, type UnscannableReason } from "./canonicalize.js";
import { parseScanResult, PROVIDER_ERROR_CODES, PROVIDER_IDS, PROVIDER_SOURCES, PROVIDER_STATES, type ProviderErrorCode, type ProviderId, type ProviderSource, type ProviderState, type ScanResult } from "./contracts.js";
import { replayFetchMachine, type JournalEntry, type MachineEffect, type MachineEvidence, type MachineFact, type MachineLimits } from "../worker/fetch/fetch-machine.js";

export const SCAN_LIMITS = { input_chars: 205_000, html_chars: 200_000, occurrences: 256, href_chars: 2_048, anchor_text_chars: 512, results: 16 } as const;
export const SCAN_LIMITATIONS = {
  anchor_text: "Anchor text was truncated to 512 characters.",
  occurrences: "Only the first 256 occurrences were retained; the source contained at least 257.",
  results: "Only the first 16 bounded results were retained.",
} as const;

export type ScanInput = { version: 1; kind: "paste_url"; analyzed_at: string; request_url: string; fetch: { started: number; limits: MachineLimits; journal: readonly JournalEntry[] } } | { version: 1; kind: "paste_html"; analyzed_at: string; base_url: string; html: string };
export type ExtractAtom = { kind: "ANCHOR"; href: string | null; href_overflow: boolean; text: string; text_overflow: boolean } | { kind: "OCCURRENCE_OVERFLOW" };
export type ExtractEffect = { kind: "EXTRACT_HTML"; id: number; source: "paste_url" | "paste_html"; base_url: string; document_url: string; extracted_at: string; body: { kind: "fetch_body"; token: string; length: number; digest: string } | { kind: "inline_html"; html: string }; limits: { occurrences: 256; href_chars: 2048; anchor_text_chars: 512 } };
export type ProviderPrimitive = { provider: ProviderId; source: ProviderSource; queried_target: string; observed_at: string; expires_at: string | null; state: ProviderState; category: string | null; reference: string | null; error: ProviderErrorCode | null };
export type ProviderEffect = { kind: "OBSERVE_PROVIDER"; id: number; target_ordinal: number; canonical_target: string; requested_at: string };
export type AllocateIdsEffect = { kind: "ALLOCATE_IDS"; id: number; count: number };
export type ScanEffect = ExtractEffect | ProviderEffect | AllocateIdsEffect;
export type ScanFact = { kind: "EXTRACTED"; effect_id: number; atoms: readonly ExtractAtom[] } | { kind: "PROVIDER_OBSERVED"; effect_id: number; observation: ProviderPrimitive } | { kind: "IDS_ALLOCATED"; effect_id: number; ids: readonly string[] };
export interface ScanJournalEntry {
  effect: ScanEffect;
  fact: ScanFact;
}
export type OccurrenceCount = { kind: "exact"; count: number } | { kind: "at_least"; count: 257 };
export interface ScanExchange {
  version: 1;
  receipt: {
    receipt_id: string;
    mode: "paste_url" | "paste_html";
    scan_ids: string[];
    occurrence_count: OccurrenceCount;
    accepted_targets: number;
    rejected_candidates: number;
    truncated: boolean;
    unscannable_reason: UnscannableReason | null;
    fetch_evidence: MachineEvidence | null;
    targets: { target_ordinal: number; canonical_url: string; occurrences: { occurrence_index: number; raw_href: string; anchor_text: string; anchor_text_overflow: boolean }[]; anchor_text_variants: string[] }[];
    rejections: { rejection_ordinal: number; occurrence_index: number; reason: UnscannableReason }[];
  };
  entries: { result_ordinal: number; result_id: string; outcome: { kind: "target"; target_ordinal: number } | { kind: "rejection"; rejection_ordinal: number } | { kind: "source"; reason: UnscannableReason }; result: ScanResult }[];
}

type Rejection = { rejection_ordinal: number; occurrence_index: number; reason: UnscannableReason };
type Outcome = { kind: "target"; target_ordinal: number } | { kind: "rejection"; rejection_ordinal: number } | { kind: "source"; reason: UnscannableReason };
interface Context {
  input: ScanInput;
  mode: "paste_url" | "paste_html";
  base_url: string;
  document_url: string;
  evidence: MachineEvidence | null;
  occurrence_count: OccurrenceCount;
  groups: CanonicalCandidateTarget[];
  rejections: Rejection[];
  outcomes: Outcome[];
  observations: ProviderPrimitive[];
  text_overflow: number[];
}
export interface ScanMachine {
  version: 1;
  phase: "AWAIT_EXTRACT" | "AWAIT_PROVIDER" | "AWAIT_IDS" | "DONE";
  next_effect_id: number;
  pending: ScanEffect | null;
  context: Context;
  provider_cursor: number;
  exchange: ScanExchange | null;
}

type R = Record<string, unknown>;
const object = (value: unknown, path: string): R => {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new TypeError(`${path} must be an object`);
  return value as R;
};
const keys = (value: R, expected: readonly string[], path: string) => {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) throw new TypeError(`${path} has unknown or missing fields`);
};
const string = (value: unknown, path: string) => {
  if (typeof value !== "string") throw new TypeError(`${path} must be a string`);
  return value;
};
const integer = (value: unknown, path: string, positive = false) => {
  if (!Number.isSafeInteger(value) || (value as number) < (positive ? 1 : 0)) throw new TypeError(`${path} must be ${positive ? "a positive" : "a non-negative"} integer`);
  return value as number;
};
const boolean = (value: unknown, path: string) => {
  if (typeof value !== "boolean") throw new TypeError(`${path} must be a boolean`);
  return value;
};
const literal = <T extends string>(value: unknown, allowed: readonly T[], path: string): T => {
  if (typeof value !== "string" || !allowed.includes(value as T)) throw new TypeError(`${path} has an invalid literal`);
  return value as T;
};
const nullable = (value: unknown, path: string) => (value === null ? null : string(value, path));
const array = <T>(value: unknown, path: string, parser: (item: unknown, path: string) => T): T[] => {
  if (!Array.isArray(value)) throw new TypeError(`${path} must be an array`);
  return value.map((item, index) => parser(item, `${path}[${index}]`));
};
const freeze = <T>(value: T): T => {
  if (typeof value === "object" && value !== null && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) freeze(child);
    Object.freeze(value);
  }
  return value;
};
const frozen = <T>(value: T): T => freeze(structuredClone(value));
const same = (left: unknown, right: unknown): boolean => {
  if (Object.is(left, right)) return true;
  if (typeof left !== "object" || left === null || typeof right !== "object" || right === null || Array.isArray(left) !== Array.isArray(right)) return false;
  if (Array.isArray(left) && Array.isArray(right)) return left.length === right.length && left.every((item, index) => same(item, right[index]));
  const leftRecord = left as R;
  const rightRecord = right as R;
  const names = Object.keys(leftRecord).sort();
  const other = Object.keys(rightRecord).sort();
  return names.length === other.length && names.every((name, index) => name === other[index] && same(leftRecord[name], rightRecord[name]));
};
const iso = (value: unknown, path: string) => {
  const parsed = string(value, path);
  let normalized: string;
  try {
    normalized = new Date(parsed).toISOString();
  } catch {
    throw new TypeError(`${path} must be a canonical timestamp`);
  }
  if (normalized !== parsed) throw new TypeError(`${path} must be a canonical timestamp`);
  return parsed;
};

function parseLimits(value: unknown, path: string): MachineLimits {
  const data = object(value, path);
  keys(data, ["max_url_chars", "max_redirects", "max_response_bytes", "operation_ms", "total_ms"], path);
  return { max_url_chars: integer(data.max_url_chars, `${path}.max_url_chars`, true), max_redirects: integer(data.max_redirects, `${path}.max_redirects`, true), max_response_bytes: integer(data.max_response_bytes, `${path}.max_response_bytes`, true), operation_ms: integer(data.operation_ms, `${path}.operation_ms`, true), total_ms: integer(data.total_ms, `${path}.total_ms`, true) };
}
function parseFetchEffect(value: unknown, path: string): MachineEffect {
  const data = object(value, path);
  const kind = literal(data.kind, ["dns", "fetch", "metadata", "discard", "read"] as const, `${path}.kind`);
  const common = { id: integer(data.id, `${path}.id`, true), issued_at: integer(data.issued_at, `${path}.issued_at`) };
  if (kind === "dns") {
    keys(data, ["kind", "id", "issued_at", "deadline", "hostname"], path);
    return { kind, hostname: string(data.hostname, `${path}.hostname`), deadline: integer(data.deadline, `${path}.deadline`), ...common };
  }
  if (kind === "fetch") {
    keys(data, ["kind", "id", "issued_at", "deadline", "url"], path);
    return { kind, url: string(data.url, `${path}.url`), deadline: integer(data.deadline, `${path}.deadline`), ...common };
  }
  if (kind === "discard") {
    keys(data, ["kind", "id", "issued_at"], path);
    return { kind, ...common };
  }
  if (kind === "metadata") {
    keys(data, ["kind", "id", "issued_at", "limits"], path);
    const limits = object(data.limits, `${path}.limits`);
    for (const [name, size] of Object.entries(limits)) integer(size, `${path}.limits.${name}`, true);
    return { kind, limits: structuredClone(limits) as Record<string, number>, ...common };
  }
  keys(data, ["kind", "id", "issued_at", "deadline", "maximum", "declared_length", "token"], path);
  return { kind, maximum: integer(data.maximum, `${path}.maximum`, true), declared_length: data.declared_length === null ? null : integer(data.declared_length, `${path}.declared_length`), deadline: integer(data.deadline, `${path}.deadline`), token: string(data.token, `${path}.token`), ...common };
}
function parseFetchFact(value: unknown, effect: MachineEffect, path: string): MachineFact {
  const data = object(value, path);
  if (data.kind !== effect.kind) throw new TypeError(`${path} is not bound to its effect`);
  if (effect.kind === "dns") {
    keys(data, ["kind", "completed_at", "addresses", "overflow", "failure"], path);
    const addresses = array(data.addresses, `${path}.addresses`, string);
    if (addresses.length > 33) throw new RangeError(`${path}.addresses is over limit`);
    return { kind: "dns", completed_at: integer(data.completed_at, `${path}.completed_at`), addresses, overflow: boolean(data.overflow, `${path}.overflow`), failure: data.failure === null ? null : literal(data.failure, ["timeout", "network_error", "capacity", "sealed", "invalid"] as const, `${path}.failure`) };
  }
  if (effect.kind === "fetch") {
    keys(data, ["kind", "completed_at", "failure"], path);
    return { kind: "fetch", completed_at: integer(data.completed_at, `${path}.completed_at`), failure: data.failure === null ? null : literal(data.failure, ["timeout", "network_error", "capacity", "sealed", "invalid"] as const, `${path}.failure`) };
  }
  if (effect.kind === "discard") {
    keys(data, ["kind", "completed_at"], path);
    return { kind: "discard", completed_at: integer(data.completed_at, `${path}.completed_at`) };
  }
  if (effect.kind === "metadata") {
    keys(data, ["kind", "completed_at", "status", "headers", "failure"], path);
    const headers = object(data.headers, `${path}.headers`);
    keys(headers, Object.keys(effect.limits), `${path}.headers`);
    const parsed: Record<string, { value: string | null; overflow: boolean }> = {};
    for (const [name, raw] of Object.entries(headers)) {
      const atom = object(raw, `${path}.headers.${name}`);
      keys(atom, ["value", "overflow"], `${path}.headers.${name}`);
      parsed[name] = { value: nullable(atom.value, `${path}.headers.${name}.value`), overflow: boolean(atom.overflow, `${path}.headers.${name}.overflow`) };
    }
    return { kind: "metadata", completed_at: integer(data.completed_at, `${path}.completed_at`), status: integer(data.status, `${path}.status`), headers: parsed, failure: data.failure === null ? null : literal(data.failure, ["invalid"] as const, `${path}.failure`) };
  }
  keys(data, ["kind", "completed_at", "failure", "token", "length", "digest", "valid_utf8"], path);
  return { kind: "read", completed_at: integer(data.completed_at, `${path}.completed_at`), failure: data.failure === null ? null : literal(data.failure, ["timeout", "limit", "invalid"] as const, `${path}.failure`), token: string(data.token, `${path}.token`), length: integer(data.length, `${path}.length`), digest: string(data.digest, `${path}.digest`), valid_utf8: boolean(data.valid_utf8, `${path}.valid_utf8`) };
}
function parseFetchJournal(value: unknown, path: string): JournalEntry[] {
  return array(value, path, (raw, itemPath) => {
    const data = object(raw, itemPath);
    keys(data, ["effect", "fact"], itemPath);
    const effect = parseFetchEffect(data.effect, `${itemPath}.effect`);
    return { effect, fact: parseFetchFact(data.fact, effect, `${itemPath}.fact`) };
  });
}
function parseInput(value: unknown): ScanInput {
  const data = object(value, "input");
  const kind = literal(data.kind, ["paste_url", "paste_html"] as const, "input.kind");
  if (kind === "paste_html") {
    keys(data, ["version", "kind", "analyzed_at", "base_url", "html"], "input");
    if (data.version !== 1) throw new TypeError("input.version must be 1");
    const html = string(data.html, "input.html");
    if (html.length > SCAN_LIMITS.input_chars) throw new RangeError("input.html is over limit");
    return { version: 1, kind, analyzed_at: iso(data.analyzed_at, "input.analyzed_at"), base_url: string(data.base_url, "input.base_url"), html };
  }
  keys(data, ["version", "kind", "analyzed_at", "request_url", "fetch"], "input");
  if (data.version !== 1) throw new TypeError("input.version must be 1");
  const fetch = object(data.fetch, "input.fetch");
  keys(fetch, ["started", "limits", "journal"], "input.fetch");
  return { version: 1, kind, analyzed_at: iso(data.analyzed_at, "input.analyzed_at"), request_url: string(data.request_url, "input.request_url"), fetch: { started: integer(fetch.started, "input.fetch.started"), limits: parseLimits(fetch.limits, "input.fetch.limits"), journal: parseFetchJournal(fetch.journal, "input.fetch.journal") } };
}

type NewEffect<T> = T extends unknown ? Omit<T, "id"> : never;
function queued(context: Context, id: number, effect: NewEffect<ScanEffect>, phase: ScanMachine["phase"]): ScanMachine {
  return frozen({ version: 1, phase, next_effect_id: id + 1, pending: { ...effect, id } as ScanEffect, context, provider_cursor: 0, exchange: null });
}
function allocation(machine: ScanMachine): ScanMachine {
  const next = structuredClone(machine);
  next.phase = "AWAIT_IDS";
  next.pending = { kind: "ALLOCATE_IDS", id: next.next_effect_id, count: 1 + next.context.outcomes.length };
  next.next_effect_id += 1;
  return frozen(next);
}
function sourceContext(input: ScanInput, mode: Context["mode"], reason: UnscannableReason, evidence: MachineEvidence | null, base = ""): Context {
  return { input, mode, base_url: base, document_url: base, evidence, occurrence_count: { kind: "exact", count: 0 }, groups: [], rejections: [], outcomes: [{ kind: "source", reason }], observations: [], text_overflow: [] };
}

export function createScanMachine(value: unknown): ScanMachine {
  const input = frozen(parseInput(value));
  let context: Context;
  let body: ExtractEffect["body"];
  if (input.kind === "paste_url") {
    const result = replayFetchMachine(input.request_url, input.fetch.limits, input.fetch.started, input.fetch.journal);
    if (!result.ok) return allocation(frozen({ version: 1, phase: "AWAIT_IDS", next_effect_id: 1, pending: null, context: sourceContext(input, input.kind, result.reason, result.evidence), provider_cursor: 0, exchange: null }));
    context = { input, mode: input.kind, base_url: result.evidence.final_url, document_url: result.evidence.final_url, evidence: result.evidence, occurrence_count: { kind: "exact", count: 0 }, groups: [], rejections: [], outcomes: [], observations: [], text_overflow: [] };
    body = { kind: "fetch_body", token: result.token, length: result.length, digest: result.digest };
  } else {
    if (input.html.length > SCAN_LIMITS.html_chars) return allocation(frozen({ version: 1, phase: "AWAIT_IDS", next_effect_id: 1, pending: null, context: sourceContext(input, input.kind, "input_too_large", null), provider_cursor: 0, exchange: null }));
    const base = input.base_url.length <= SCAN_LIMITS.href_chars ? canonicalizeUrl(input.base_url) : { ok: false as const, reason: "url_too_long" as const };
    if (!base.ok || base.target.canonical_url.length > SCAN_LIMITS.href_chars) {
      const reason = base.ok ? "url_too_long" : base.reason;
      return allocation(frozen({ version: 1, phase: "AWAIT_IDS", next_effect_id: 1, pending: null, context: sourceContext(input, input.kind, reason, null), provider_cursor: 0, exchange: null }));
    }
    context = { input, mode: input.kind, base_url: base.target.canonical_url, document_url: base.target.canonical_url, evidence: null, occurrence_count: { kind: "exact", count: 0 }, groups: [], rejections: [], outcomes: [], observations: [], text_overflow: [] };
    body = { kind: "inline_html", html: input.html };
  }
  return queued(context, 1, { kind: "EXTRACT_HTML", source: context.mode, base_url: context.base_url, document_url: context.document_url, extracted_at: input.analyzed_at, body, limits: { occurrences: 256, href_chars: 2048, anchor_text_chars: 512 } }, "AWAIT_EXTRACT");
}

function parseEffect(value: unknown, path = "effect"): ScanEffect {
  const data = object(value, path);
  const kind = literal(data.kind, ["EXTRACT_HTML", "OBSERVE_PROVIDER", "ALLOCATE_IDS"] as const, `${path}.kind`);
  const id = integer(data.id, `${path}.id`, true);
  if (kind === "OBSERVE_PROVIDER") {
    keys(data, ["kind", "id", "target_ordinal", "canonical_target", "requested_at"], path);
    return { kind, id, target_ordinal: integer(data.target_ordinal, `${path}.target_ordinal`), canonical_target: string(data.canonical_target, `${path}.canonical_target`), requested_at: iso(data.requested_at, `${path}.requested_at`) };
  }
  if (kind === "ALLOCATE_IDS") {
    keys(data, ["kind", "id", "count"], path);
    const count = integer(data.count, `${path}.count`, true);
    if (count < 2 || count > 17) throw new RangeError(`${path}.count is over limit`);
    return { kind, id, count };
  }
  keys(data, ["kind", "id", "source", "base_url", "document_url", "extracted_at", "body", "limits"], path);
  const limits = object(data.limits, `${path}.limits`);
  keys(limits, ["occurrences", "href_chars", "anchor_text_chars"], `${path}.limits`);
  if (limits.occurrences !== 256 || limits.href_chars !== 2048 || limits.anchor_text_chars !== 512) throw new TypeError(`${path}.limits are invalid`);
  const rawBody = object(data.body, `${path}.body`);
  const bodyKind = literal(rawBody.kind, ["fetch_body", "inline_html"] as const, `${path}.body.kind`);
  let body: ExtractEffect["body"];
  if (bodyKind === "inline_html") {
    keys(rawBody, ["kind", "html"], `${path}.body`);
    const html = string(rawBody.html, `${path}.body.html`);
    if (html.length > SCAN_LIMITS.html_chars) throw new RangeError(`${path}.body.html is over limit`);
    body = { kind: bodyKind, html };
  } else {
    keys(rawBody, ["kind", "token", "length", "digest"], `${path}.body`);
    body = { kind: bodyKind, token: string(rawBody.token, `${path}.body.token`), length: integer(rawBody.length, `${path}.body.length`), digest: string(rawBody.digest, `${path}.body.digest`) };
  }
  return { kind, id, source: literal(data.source, ["paste_url", "paste_html"] as const, `${path}.source`), base_url: string(data.base_url, `${path}.base_url`), document_url: string(data.document_url, `${path}.document_url`), extracted_at: iso(data.extracted_at, `${path}.extracted_at`), body, limits: { occurrences: 256, href_chars: 2048, anchor_text_chars: 512 } };
}
function parseFact(value: unknown, effect: ScanEffect, path = "fact"): ScanFact {
  const data = object(value, path);
  if (effect.kind === "EXTRACT_HTML") {
    keys(data, ["kind", "effect_id", "atoms"], path);
    if (data.kind !== "EXTRACTED") throw new TypeError(`${path} is not bound to its effect`);
    const atoms = array(data.atoms, `${path}.atoms`, (raw, atomPath): ExtractAtom => {
      const atom = object(raw, atomPath);
      if (atom.kind === "OCCURRENCE_OVERFLOW") {
        keys(atom, ["kind"], atomPath);
        return { kind: "OCCURRENCE_OVERFLOW" };
      }
      keys(atom, ["kind", "href", "href_overflow", "text", "text_overflow"], atomPath);
      if (atom.kind !== "ANCHOR") throw new TypeError(`${atomPath}.kind is invalid`);
      const overflow = boolean(atom.href_overflow, `${atomPath}.href_overflow`);
      const href = nullable(atom.href, `${atomPath}.href`);
      if ((overflow && href !== null) || (!overflow && href === null) || (href !== null && href.length > SCAN_LIMITS.href_chars)) throw new TypeError(`${atomPath}.href binding is invalid`);
      const text = string(atom.text, `${atomPath}.text`);
      if (text.length > SCAN_LIMITS.anchor_text_chars) throw new RangeError(`${atomPath}.text is over limit`);
      return { kind: "ANCHOR", href, href_overflow: overflow, text, text_overflow: boolean(atom.text_overflow, `${atomPath}.text_overflow`) };
    });
    const sentinel = atoms.findIndex((atom) => atom.kind === "OCCURRENCE_OVERFLOW");
    if (atoms.length > 257 || (sentinel >= 0 && (sentinel !== 256 || atoms.length !== 257)) || (sentinel < 0 && atoms.length > 256)) throw new TypeError(`${path}.atoms has an invalid occurrence boundary`);
    return { kind: "EXTRACTED", effect_id: integer(data.effect_id, `${path}.effect_id`, true), atoms };
  }
  if (effect.kind === "OBSERVE_PROVIDER") {
    keys(data, ["kind", "effect_id", "observation"], path);
    if (data.kind !== "PROVIDER_OBSERVED") throw new TypeError(`${path} is not bound to its effect`);
    const raw = object(data.observation, `${path}.observation`);
    keys(raw, ["provider", "source", "queried_target", "observed_at", "expires_at", "state", "category", "reference", "error"], `${path}.observation`);
    const observation: ProviderPrimitive = {
      provider: literal(raw.provider, PROVIDER_IDS, `${path}.observation.provider`),
      source: literal(raw.source, PROVIDER_SOURCES, `${path}.observation.source`),
      queried_target: string(raw.queried_target, `${path}.observation.queried_target`),
      observed_at: string(raw.observed_at, `${path}.observation.observed_at`),
      expires_at: nullable(raw.expires_at, `${path}.observation.expires_at`),
      state: literal(raw.state, PROVIDER_STATES, `${path}.observation.state`),
      category: nullable(raw.category, `${path}.observation.category`),
      reference: nullable(raw.reference, `${path}.observation.reference`),
      error: raw.error === null ? null : literal(raw.error, PROVIDER_ERROR_CODES, `${path}.observation.error`),
    };
    if (observation.queried_target !== effect.canonical_target) throw new TypeError(`${path}.observation target mismatch`);
    return { kind: "PROVIDER_OBSERVED", effect_id: integer(data.effect_id, `${path}.effect_id`, true), observation };
  }
  keys(data, ["kind", "effect_id", "ids"], path);
  if (data.kind !== "IDS_ALLOCATED") throw new TypeError(`${path} is not bound to its effect`);
  const ids = array(data.ids, `${path}.ids`, string);
  if (ids.length !== effect.count || new Set(ids).size !== ids.length || ids.some((id) => !/^[0-9a-f]{32}$/u.test(id))) throw new TypeError(`${path}.ids are invalid`);
  return { kind: "IDS_ALLOCATED", effect_id: integer(data.effect_id, `${path}.effect_id`, true), ids };
}

function afterExtraction(machine: ScanMachine, fact: Extract<ScanFact, { kind: "EXTRACTED" }>): ScanMachine {
  const next = structuredClone(machine);
  const anchors = fact.atoms.filter((atom): atom is Extract<ExtractAtom, { kind: "ANCHOR" }> => atom.kind === "ANCHOR");
  const candidates = anchors.flatMap((atom, index) => (atom.href === null ? [] : [{ raw_href: atom.href, anchor_text: atom.text, base_url: next.context.base_url, provenance: { source: next.context.mode, document_url: next.context.document_url, occurrence_index: index, extracted_at: next.context.input.analyzed_at } }]));
  const collection = collectLinkCandidates(candidates);
  const groups = collection.targets.filter((target) => target.canonical_url.length <= SCAN_LIMITS.href_chars);
  const rejected: Omit<Rejection, "rejection_ordinal">[] = collection.rejected.map(({ candidate, reason }) => ({ occurrence_index: candidate.provenance.occurrence_index, reason }));
  for (const target of collection.targets) if (target.canonical_url.length > SCAN_LIMITS.href_chars) for (const occurrence of target.occurrences) rejected.push({ occurrence_index: occurrence.candidate.provenance.occurrence_index, reason: "url_too_long" });
  anchors.forEach((atom, index) => {
    if (atom.href_overflow) rejected.push({ occurrence_index: index, reason: "url_too_long" });
  });
  rejected.sort((a, b) => a.occurrence_index - b.occurrence_index);
  next.context.groups = groups;
  next.context.rejections = rejected.map((item, rejection_ordinal) => ({ ...item, rejection_ordinal }));
  const outcomes: Outcome[] = [...groups.map((_, target_ordinal): Outcome => ({ kind: "target", target_ordinal })), ...next.context.rejections.map(({ rejection_ordinal }): Outcome => ({ kind: "rejection", rejection_ordinal }))];
  next.context.outcomes = outcomes.length === 0 ? [{ kind: "source", reason: "no_candidates" }] : outcomes.slice(0, SCAN_LIMITS.results);
  next.context.occurrence_count = fact.atoms.at(-1)?.kind === "OCCURRENCE_OVERFLOW" ? { kind: "at_least", count: 257 } : { kind: "exact", count: anchors.length };
  next.context.text_overflow = anchors.flatMap((atom, index) => (atom.text_overflow ? [index] : []));
  next.provider_cursor = 0;
  if (next.context.outcomes[0]?.kind === "target") {
    const target = groups[0]!;
    next.phase = "AWAIT_PROVIDER";
    next.pending = { kind: "OBSERVE_PROVIDER", id: next.next_effect_id, target_ordinal: 0, canonical_target: target.canonical_url, requested_at: next.context.input.analyzed_at };
    next.next_effect_id += 1;
    return frozen(next);
  }
  return allocation(frozen(next));
}
function resultFor(context: Context, outcome: Outcome, id: string): ScanResult {
  if (outcome.kind !== "target") return aggregateAnalysis({ scan_id: id, mode: context.mode, analyzed_at: context.input.analyzed_at, target: null, unscannable_reason: outcome.kind === "source" ? outcome.reason : context.rejections[outcome.rejection_ordinal]!.reason });
  const target = context.groups[outcome.target_ordinal]!;
  const primitive = context.observations[outcome.target_ordinal]!;
  return aggregateAnalysis({ scan_id: id, mode: context.mode, analyzed_at: context.input.analyzed_at, target, provider_observations: [{ ...primitive, freshness: "unknown", confidence: "low" }] });
}
function terminal(machine: ScanMachine, ids: readonly string[]): ScanMachine {
  const next = structuredClone(machine);
  const sentinel = next.context.occurrence_count.kind === "at_least";
  const total = next.context.groups.length + next.context.rejections.length;
  const entries = next.context.outcomes.map((outcome, result_ordinal) => {
    const result_id = ids[result_ordinal + 1]!;
    const result = resultFor(next.context, outcome, result_id);
    if (outcome.kind === "target" && next.context.groups[outcome.target_ordinal]!.occurrences.some(({ candidate }) => next.context.text_overflow.includes(candidate.provenance.occurrence_index))) result.limitations.push(SCAN_LIMITATIONS.anchor_text);
    if (sentinel) result.limitations.push(SCAN_LIMITATIONS.occurrences);
    if (total > SCAN_LIMITS.results) result.limitations.push(SCAN_LIMITATIONS.results);
    return { result_ordinal, result_id, outcome, result: parseScanResult(result) };
  });
  const representedTargets = new Set(next.context.outcomes.flatMap((outcome) => (outcome.kind === "target" ? [outcome.target_ordinal] : [])));
  const representedRejections = new Set(next.context.outcomes.flatMap((outcome) => (outcome.kind === "rejection" ? [outcome.rejection_ordinal] : [])));
  const targets = next.context.groups.flatMap((target, target_ordinal) =>
    representedTargets.has(target_ordinal) ? [{ target_ordinal, canonical_url: target.canonical_url, occurrences: target.occurrences.map(({ candidate }) => ({ occurrence_index: candidate.provenance.occurrence_index, raw_href: candidate.raw_href, anchor_text: candidate.anchor_text, anchor_text_overflow: next.context.text_overflow.includes(candidate.provenance.occurrence_index) })), anchor_text_variants: [...target.anchor_text_variants] }] : [],
  );
  const rejections = next.context.rejections.filter(({ rejection_ordinal }) => representedRejections.has(rejection_ordinal));
  const only = next.context.groups.length === 0 && next.context.rejections.length === 1 ? next.context.rejections[0]!.reason : next.context.outcomes[0]?.kind === "source" ? next.context.outcomes[0].reason : null;
  next.exchange = { version: 1, receipt: { receipt_id: ids[0]!, mode: next.context.mode, scan_ids: ids.slice(1) as string[], occurrence_count: next.context.occurrence_count, accepted_targets: next.context.groups.length, rejected_candidates: next.context.rejections.length, truncated: sentinel || total > SCAN_LIMITS.results, unscannable_reason: only, fetch_evidence: next.context.evidence, targets, rejections }, entries };
  next.phase = "DONE";
  next.pending = null;
  return frozen(next);
}

export function reduceScanMachine(source: ScanMachine, value: unknown): ScanMachine {
  if (source.exchange !== null || source.pending === null) throw new TypeError("invalid machine transition");
  const effect = parseEffect(source.pending);
  const fact = parseFact(value, effect);
  if (fact.effect_id !== effect.id) throw new TypeError("fact effect mismatch");
  if (effect.kind === "EXTRACT_HTML" && fact.kind === "EXTRACTED") return afterExtraction(source, fact);
  if (effect.kind === "OBSERVE_PROVIDER" && fact.kind === "PROVIDER_OBSERVED") {
    const next = structuredClone(source);
    next.context.observations.push(fact.observation);
    next.provider_cursor += 1;
    const following = next.context.outcomes[next.provider_cursor];
    if (following?.kind === "target") {
      const target = next.context.groups[following.target_ordinal]!;
      next.pending = { kind: "OBSERVE_PROVIDER", id: next.next_effect_id, target_ordinal: following.target_ordinal, canonical_target: target.canonical_url, requested_at: next.context.input.analyzed_at };
      next.next_effect_id += 1;
      return frozen(next);
    }
    return allocation(frozen(next));
  }
  if (effect.kind === "ALLOCATE_IDS" && fact.kind === "IDS_ALLOCATED") return terminal(source, fact.ids);
  throw new TypeError("invalid machine fact");
}
export function scanJournalEntry(effectValue: unknown, factValue: unknown): ScanJournalEntry {
  const effect = parseEffect(effectValue);
  const fact = parseFact(factValue, effect);
  if (fact.effect_id !== effect.id) throw new TypeError("fact effect mismatch");
  return frozen({ effect, fact });
}
export function replayScanMachine(input: unknown, journal: readonly unknown[]): ScanExchange {
  if (!Array.isArray(journal)) throw new TypeError("journal must be an array");
  let machine = createScanMachine(input);
  for (const raw of journal) {
    const entryData = object(raw, "journal entry");
    keys(entryData, ["effect", "fact"], "journal entry");
    const entry = scanJournalEntry(entryData.effect, entryData.fact);
    if (machine.pending === null || !same(machine.pending, entry.effect)) throw new TypeError("journal effect mismatch");
    machine = reduceScanMachine(machine, entry.fact);
  }
  if (machine.phase !== "DONE" || machine.pending !== null || machine.exchange === null) throw new TypeError("journal incomplete");
  return frozen(machine.exchange);
}

function validateClaim(value: unknown): void {
  const data = object(value, "exchange");
  keys(data, ["version", "receipt", "entries"], "exchange");
  if (data.version !== 1) throw new TypeError("exchange.version must be 1");
  const receipt = object(data.receipt, "exchange.receipt");
  keys(receipt, ["receipt_id", "mode", "scan_ids", "occurrence_count", "accepted_targets", "rejected_candidates", "truncated", "unscannable_reason", "fetch_evidence", "targets", "rejections"], "exchange.receipt");
  array(receipt.scan_ids, "exchange.receipt.scan_ids", string);
  const count = object(receipt.occurrence_count, "exchange.receipt.occurrence_count");
  keys(count, ["kind", "count"], "exchange.receipt.occurrence_count");
  array(receipt.targets, "exchange.receipt.targets", (raw, path) => {
    const item = object(raw, path);
    keys(item, ["target_ordinal", "canonical_url", "occurrences", "anchor_text_variants"], path);
    array(item.occurrences, `${path}.occurrences`, (occ, occPath) => {
      const atom = object(occ, occPath);
      keys(atom, ["occurrence_index", "raw_href", "anchor_text", "anchor_text_overflow"], occPath);
      return atom;
    });
    array(item.anchor_text_variants, `${path}.anchor_text_variants`, string);
    return item;
  });
  array(receipt.rejections, "exchange.receipt.rejections", (raw, path) => {
    const item = object(raw, path);
    keys(item, ["rejection_ordinal", "occurrence_index", "reason"], path);
    return item;
  });
  array(data.entries, "exchange.entries", (raw, path) => {
    const item = object(raw, path);
    keys(item, ["result_ordinal", "result_id", "outcome", "result"], path);
    const outcome = object(item.outcome, `${path}.outcome`);
    if (outcome.kind === "target") keys(outcome, ["kind", "target_ordinal"], `${path}.outcome`);
    else if (outcome.kind === "rejection") keys(outcome, ["kind", "rejection_ordinal"], `${path}.outcome`);
    else if (outcome.kind === "source") keys(outcome, ["kind", "reason"], `${path}.outcome`);
    else throw new TypeError(`${path}.outcome.kind is invalid`);
    parseScanResult(item.result);
    return item;
  });
}
export function verifyScanExchange(input: unknown, journal: readonly unknown[], claimed: unknown): ScanExchange {
  validateClaim(claimed);
  const derived = replayScanMachine(input, journal);
  if (!same(derived, claimed)) throw new TypeError("scan exchange mismatch");
  return derived;
}
