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
export function reduceFetchMachine(source: FetchMachine, fact: MachineFact): FetchMachine {
  const machine = copy(source); const effect = machine.pending;
  if (machine.terminal !== null || effect === null || effect.kind !== fact.kind) throw new TypeError("invalid machine transition");
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
export function replayFetchMachine(rawUrl: string, limits: MachineLimits, started: number, entries: readonly JournalEntry[]): MachineResult {
  let machine = createFetchMachine(rawUrl, limits, started);
  for (const entry of entries) {
    if (machine.pending === null || JSON.stringify(machine.pending) !== JSON.stringify(entry.effect)) throw new TypeError("journal effect mismatch");
    machine = reduceFetchMachine(machine, structuredClone(entry.fact));
  }
  if (machine.terminal === null || machine.pending !== null) throw new TypeError("journal incomplete");
  return machine.terminal;
}
