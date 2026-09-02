import { canonicalizeUrl, type UnscannableReason } from "../../shared/canonicalize.js";
import { isPublicAddress, literalAddress, SPECIAL_NAMES } from "./address.js";
import type { HeaderAtom } from "./response-scope.js";

export interface MachineLimits { max_url_chars: number; max_redirects: number; max_response_bytes: number; operation_ms: number; total_ms: number }
export interface MachineEvidence { requested_url: string; final_url: string; redirect_chain: string[]; validated_hops: { hostname: string; address_count: number }[] }
type Failure = { ok: false; reason: UnscannableReason; evidence: MachineEvidence };
export type MachineResult = Failure | { ok: true; token: string; length: number; digest: string; evidence: MachineEvidence };
type BaseEffect = { id: number; issued_at: number; deadline?: number };
export type MachineEffect = BaseEffect & (
  | { kind: "dns"; hostname: string }
  | { kind: "fetch"; url: string }
  | { kind: "metadata"; limits: Record<string, number> }
  | { kind: "discard" }
  | { kind: "read"; maximum: number; declared_length: number | null; token: string }
);
type TimedFailure = "timeout" | "network_error" | "capacity" | "sealed" | "invalid";
export type MachineFact =
  | { kind: "dns"; completed_at: number; addresses: string[]; overflow: boolean; failure: TimedFailure | null }
  | { kind: "fetch"; completed_at: number; failure: TimedFailure | null }
  | { kind: "metadata"; completed_at: number; status: number; headers: Record<string, HeaderAtom>; failure: "invalid" | null }
  | { kind: "discard"; completed_at: number }
  | { kind: "read"; completed_at: number; failure: "timeout" | "limit" | "invalid" | null; token: string; length: number; digest: string; valid_utf8: boolean };
type AfterDiscard = { kind: "fail"; reason: UnscannableReason } | { kind: "redirect"; url: string };
export interface FetchMachine { limits: MachineLimits; started: number; current: string; visited: string[]; redirects: number; evidence: MachineEvidence; next_id: number; pending: MachineEffect | null; after_discard: AfterDiscard | null; terminal: MachineResult | null }
export interface JournalEntry { effect: MachineEffect; fact: MachineFact }

type RecordValue = Record<string, unknown>;
const record = (value: unknown, path: string): RecordValue => {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new TypeError(`${path} must be an object`);
  return value as RecordValue;
};
const keys = (value: RecordValue, expected: readonly string[], path: string) => {
  const actual = Object.keys(value).sort(); const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) throw new TypeError(`${path} has unknown or missing fields`);
};
const integer = (value: unknown, path: string, positive = false) => {
  if (!Number.isSafeInteger(value) || (value as number) < (positive ? 1 : 0)) throw new TypeError(`${path} must be ${positive ? "a positive" : "a non-negative"} integer`);
  return value as number;
};
const string = (value: unknown, path: string) => {
  if (typeof value !== "string") throw new TypeError(`${path} must be a string`);
  return value;
};
const boolean = (value: unknown, path: string) => {
  if (typeof value !== "boolean") throw new TypeError(`${path} must be a boolean`);
  return value;
};
const literal = <T extends string>(value: unknown, allowed: readonly T[], path: string): T => {
  if (typeof value !== "string" || !allowed.includes(value as T)) throw new TypeError(`${path} has an invalid literal`);
  return value as T;
};
const timedFailure = (value: unknown, path: string): TimedFailure | null => value === null ? null : literal(value, ["timeout", "network_error", "capacity", "sealed", "invalid"] as const, path);

function parseEffect(value: unknown, path: string): MachineEffect {
  const data = record(value, path);
  const kind = literal(data.kind, ["dns", "fetch", "metadata", "discard", "read"] as const, `${path}.kind`);
  const common = { id: integer(data.id, `${path}.id`, true), issued_at: integer(data.issued_at, `${path}.issued_at`) };
  if (kind === "dns") { keys(data, ["kind", "id", "issued_at", "deadline", "hostname"], path); return { kind, hostname: string(data.hostname, `${path}.hostname`), deadline: integer(data.deadline, `${path}.deadline`), ...common }; }
  if (kind === "fetch") { keys(data, ["kind", "id", "issued_at", "deadline", "url"], path); return { kind, url: string(data.url, `${path}.url`), deadline: integer(data.deadline, `${path}.deadline`), ...common }; }
  if (kind === "discard") { keys(data, ["kind", "id", "issued_at"], path); return { kind, ...common }; }
  if (kind === "metadata") {
    keys(data, ["kind", "id", "issued_at", "limits"], path);
    const limits = record(data.limits, `${path}.limits`); keys(limits, ["location", "content-type", "content-encoding", "content-length"], `${path}.limits`);
    const parsed: Record<string, number> = {};
    for (const [name, size] of Object.entries(limits)) parsed[name] = integer(size, `${path}.limits.${name}`, true);
    return { kind, limits: parsed, ...common };
  }
  keys(data, ["kind", "id", "issued_at", "deadline", "maximum", "declared_length", "token"], path);
  return { kind, maximum: integer(data.maximum, `${path}.maximum`, true), declared_length: data.declared_length === null ? null : integer(data.declared_length, `${path}.declared_length`), deadline: integer(data.deadline, `${path}.deadline`), token: string(data.token, `${path}.token`), ...common };
}

function parseFact(value: unknown, effect: MachineEffect, path: string): MachineFact {
  const data = record(value, path);
  if (data.kind !== effect.kind) throw new TypeError(`${path} is not bound to its effect`);
  if (effect.kind === "dns") {
    keys(data, ["kind", "completed_at", "addresses", "overflow", "failure"], path);
    if (!Array.isArray(data.addresses)) throw new TypeError(`${path}.addresses must be an array`);
    return { kind: "dns", completed_at: integer(data.completed_at, `${path}.completed_at`), addresses: data.addresses.map((item, index) => string(item, `${path}.addresses[${index}]`)), overflow: boolean(data.overflow, `${path}.overflow`), failure: timedFailure(data.failure, `${path}.failure`) };
  }
  if (effect.kind === "fetch") { keys(data, ["kind", "completed_at", "failure"], path); return { kind: "fetch", completed_at: integer(data.completed_at, `${path}.completed_at`), failure: timedFailure(data.failure, `${path}.failure`) }; }
  if (effect.kind === "discard") { keys(data, ["kind", "completed_at"], path); return { kind: "discard", completed_at: integer(data.completed_at, `${path}.completed_at`) }; }
  if (effect.kind === "metadata") {
    keys(data, ["kind", "completed_at", "status", "headers", "failure"], path);
    const headers = record(data.headers, `${path}.headers`); keys(headers, Object.keys(effect.limits), `${path}.headers`);
    const parsed: Record<string, HeaderAtom> = {};
    for (const [name, value] of Object.entries(headers)) {
      const atom = record(value, `${path}.headers.${name}`); keys(atom, ["value", "overflow"], `${path}.headers.${name}`);
      parsed[name] = { value: atom.value === null ? null : string(atom.value, `${path}.headers.${name}.value`), overflow: boolean(atom.overflow, `${path}.headers.${name}.overflow`) };
    }
    return { kind: "metadata", completed_at: integer(data.completed_at, `${path}.completed_at`), status: integer(data.status, `${path}.status`), headers: parsed, failure: data.failure === null ? null : literal(data.failure, ["invalid"] as const, `${path}.failure`) };
  }
  keys(data, ["kind", "completed_at", "failure", "token", "length", "digest", "valid_utf8"], path);
  return { kind: "read", completed_at: integer(data.completed_at, `${path}.completed_at`), failure: data.failure === null ? null : literal(data.failure, ["timeout", "limit", "invalid"] as const, `${path}.failure`), token: string(data.token, `${path}.token`), length: integer(data.length, `${path}.length`), digest: string(data.digest, `${path}.digest`), valid_utf8: boolean(data.valid_utf8, `${path}.valid_utf8`) };
}

const copiedEvidence = (value: MachineEvidence): MachineEvidence => ({ ...value, redirect_chain: [...value.redirect_chain], validated_hops: value.validated_hops.map((hop) => ({ ...hop })) });
const copy = (value: FetchMachine): FetchMachine => ({ ...value, visited: [...value.visited], evidence: copiedEvidence(value.evidence), pending: value.pending === null ? null : structuredClone(value.pending), after_discard: value.after_discard === null ? null : { ...value.after_discard }, terminal: value.terminal === null ? null : { ...value.terminal, evidence: copiedEvidence(value.terminal.evidence) } });
const failure = (machine: FetchMachine, reason: UnscannableReason) => {
  machine.pending = null; machine.terminal = { ok: false, reason, evidence: copiedEvidence(machine.evidence) };
};
const deadline = (machine: FetchMachine, at: number) => Math.min(machine.started + machine.limits.total_ms, at + machine.limits.operation_ms);
type NewEffect<T> = T extends unknown ? Omit<T, "id" | "issued_at"> : never;
const queue = (machine: FetchMachine, effect: NewEffect<MachineEffect>, at: number) => {
  if ("deadline" in effect && at >= effect.deadline!) { failure(machine, "timeout"); return; }
  machine.pending = { ...effect, id: machine.next_id, issued_at: at } as MachineEffect; machine.next_id += 1;
};
const specialName = (hostname: string) => !hostname.includes(".") || SPECIAL_NAMES.some((name) => hostname === name || hostname.endsWith(`.${name}`));
const startHop = (machine: FetchMachine, at: number) => {
  if (machine.visited.includes(machine.current)) { failure(machine, "redirect_loop"); return; }
  machine.visited.push(machine.current);
  const hostname = new URL(machine.current).hostname.toLowerCase().replace(/\.+$/u, "");
  const literal = literalAddress(hostname);
  if (literal !== null) {
    if (!isPublicAddress(literal)) { failure(machine, "unsafe_address"); return; }
    machine.evidence.validated_hops.push({ hostname, address_count: 1 });
    queue(machine, { kind: "fetch", url: machine.current, deadline: deadline(machine, at) }, at); return;
  }
  if (hostname === "" || specialName(hostname)) { failure(machine, "unsafe_address"); return; }
  queue(machine, { kind: "dns", hostname, deadline: deadline(machine, at) }, at);
};

export function createFetchMachine(rawUrl: string, limits: MachineLimits, started: number): FetchMachine {
  const initial = rawUrl.length <= limits.max_url_chars ? canonicalizeUrl(rawUrl) : { ok: false as const, reason: "url_too_long" as const };
  const requested = initial.ok ? initial.target.canonical_url : "";
  const machine: FetchMachine = { limits, started, current: requested, visited: [], redirects: 0, evidence: { requested_url: requested, final_url: requested, redirect_chain: [], validated_hops: [] }, next_id: 1, pending: null, after_discard: null, terminal: null };
  if (!initial.ok) failure(machine, initial.reason);
  else if (requested.length > limits.max_url_chars) failure(machine, "url_too_long");
  else startHop(machine, started);
  return machine;
}

const discardThen = (machine: FetchMachine, action: AfterDiscard, at: number) => {
  machine.after_discard = action; queue(machine, { kind: "discard" }, at);
};
const header = (fact: Extract<MachineFact, { kind: "metadata" }>, name: string) => fact.headers[name] ?? { value: null, overflow: false };
export function reduceFetchMachine(source: FetchMachine, value: unknown): FetchMachine {
  const machine = copy(source); const effect = machine.pending;
  if (machine.terminal !== null || effect === null) throw new TypeError("invalid machine transition");
  const fact = parseFact(value, parseEffect(effect, "pending effect"), "fact");
  machine.pending = null;
  if ("deadline" in effect && effect.deadline !== undefined && "completed_at" in fact && fact.completed_at > effect.deadline) {
    if (effect.kind === "fetch" || effect.kind === "read") discardThen(machine, { kind: "fail", reason: "timeout" }, fact.completed_at);
    else failure(machine, "timeout");
    return machine;
  }
  if (fact.kind === "dns" && effect.kind === "dns") {
    if (fact.failure !== null) { failure(machine, fact.failure === "timeout" || fact.failure === "sealed" ? "timeout" : "dns_failure"); return machine; }
    const addresses = [...new Set(fact.addresses)];
    if (fact.overflow || addresses.length === 0 || addresses.length > 32) { failure(machine, "dns_failure"); return machine; }
    const publicFlags = addresses.map(isPublicAddress);
    if (!publicFlags.every(Boolean)) { failure(machine, publicFlags.some(Boolean) ? "mixed_address" : "unsafe_address"); return machine; }
    machine.evidence.validated_hops.push({ hostname: effect.hostname, address_count: addresses.length });
    queue(machine, { kind: "fetch", url: machine.current, deadline: deadline(machine, fact.completed_at) }, fact.completed_at); return machine;
  }
  if (fact.kind === "fetch" && effect.kind === "fetch") {
    if (fact.failure !== null) { failure(machine, fact.failure === "timeout" || fact.failure === "sealed" ? "timeout" : "fetch_failed"); return machine; }
    queue(machine, { kind: "metadata", limits: { location: machine.limits.max_url_chars, "content-type": 256, "content-encoding": 128, "content-length": 32 } }, fact.completed_at); return machine;
  }
  if (fact.kind === "metadata" && effect.kind === "metadata") {
    if (fact.failure !== null) { failure(machine, "invalid_response"); return machine; }
    const location = header(fact, "location"); const type = header(fact, "content-type");
    const encoding = header(fact, "content-encoding"); const length = header(fact, "content-length");
    if (location.overflow) { discardThen(machine, { kind: "fail", reason: "url_too_long" }, fact.completed_at); return machine; }
    if (type.overflow || encoding.overflow || length.overflow) { discardThen(machine, { kind: "fail", reason: "invalid_response" }, fact.completed_at); return machine; }
    if (fact.status >= 300 && fact.status < 400) {
      if (location.value === null) { discardThen(machine, { kind: "fail", reason: "redirect_missing_location" }, fact.completed_at); return machine; }
      if (machine.redirects >= machine.limits.max_redirects) { discardThen(machine, { kind: "fail", reason: "redirect_limit" }, fact.completed_at); return machine; }
      const next = canonicalizeUrl(location.value, machine.current);
      if (!next.ok || next.target.canonical_url.length > machine.limits.max_url_chars) { discardThen(machine, { kind: "fail", reason: next.ok ? "url_too_long" : next.reason }, fact.completed_at); return machine; }
      discardThen(machine, { kind: "redirect", url: next.target.canonical_url }, fact.completed_at); return machine;
    }
    if (fact.status < 200 || fact.status >= 300) { discardThen(machine, { kind: "fail", reason: "invalid_response" }, fact.completed_at); return machine; }
    const normalizedEncoding = encoding.value?.trim().toLowerCase();
    if (normalizedEncoding !== undefined && normalizedEncoding !== "" && normalizedEncoding !== "identity") { discardThen(machine, { kind: "fail", reason: "unsupported_content_encoding" }, fact.completed_at); return machine; }
    if (type.value?.split(";", 1)[0]?.trim().toLowerCase() !== "text/html") { discardThen(machine, { kind: "fail", reason: "unsupported_content_type" }, fact.completed_at); return machine; }
    let declared: number | null = null;
    if (length.value !== null) {
      declared = Number(length.value);
      if (!Number.isSafeInteger(declared) || declared < 0) { discardThen(machine, { kind: "fail", reason: "invalid_response" }, fact.completed_at); return machine; }
      if (declared > machine.limits.max_response_bytes) { discardThen(machine, { kind: "fail", reason: "response_too_large" }, fact.completed_at); return machine; }
    }
    const nextDeadline = deadline(machine, fact.completed_at);
    queue(machine, { kind: "read", maximum: machine.limits.max_response_bytes, declared_length: declared, deadline: nextDeadline, token: `${effect.id}:${machine.current}` }, fact.completed_at); return machine;
  }
  if (fact.kind === "discard" && effect.kind === "discard") {
    const action = machine.after_discard; machine.after_discard = null;
    if (action === null) throw new TypeError("discard without disposition");
    if (action.kind === "fail") failure(machine, action.reason);
    else { machine.redirects += 1; machine.current = action.url; machine.evidence.redirect_chain.push(action.url); machine.evidence.final_url = action.url; startHop(machine, fact.completed_at); }
    return machine;
  }
  if (fact.kind === "read" && effect.kind === "read") {
    if (fact.failure !== null) { failure(machine, fact.failure === "timeout" ? "timeout" : fact.failure === "limit" ? "response_too_large" : "invalid_response"); return machine; }
    if (!fact.valid_utf8 || fact.token !== effect.token || fact.length > effect.maximum || (effect.declared_length !== null && fact.length !== effect.declared_length)) { failure(machine, "invalid_response"); return machine; }
    machine.terminal = { ok: true, token: fact.token, length: fact.length, digest: fact.digest, evidence: copiedEvidence(machine.evidence) }; return machine;
  }
  throw new TypeError("invalid machine fact");
}

const freeze = <T>(value: T): T => { if (typeof value === "object" && value !== null) { for (const child of Object.values(value)) freeze(child); Object.freeze(value); } return value; };
export const journalEntry = (effect: MachineEffect, fact: MachineFact): JournalEntry => freeze(structuredClone({ effect, fact }));
export function replayFetchMachine(rawUrl: string, limits: MachineLimits, started: number, entries: readonly unknown[]): MachineResult {
  let machine = createFetchMachine(rawUrl, limits, started);
  for (const raw of entries) {
    const entry = record(raw, "journal entry"); keys(entry, ["effect", "fact"], "journal entry");
    if (machine.pending === null || JSON.stringify(parseEffect(machine.pending, "pending effect")) !== JSON.stringify(parseEffect(entry.effect, "journal effect"))) throw new TypeError("journal effect mismatch");
    machine = reduceFetchMachine(machine, entry.fact);
  }
  if (machine.terminal === null || machine.pending !== null) throw new TypeError("journal incomplete");
  return machine.terminal;
}
