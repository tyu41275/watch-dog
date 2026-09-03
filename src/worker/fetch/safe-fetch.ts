import { resolve4, resolve6 } from "node:dns/promises";
import type { UnscannableReason } from "../../shared/canonicalize.js";
import { addressFamily, type AddressResolver } from "./address.js";
import {
  createFetchMachine, journalEntry, reduceFetchMachine,
  type JournalEntry, type MachineFact,
} from "./fetch-machine.js";
import { createResponseScope, type Fetcher, type ResponseHandle } from "./response-scope.js";

export const SAFE_FETCH_LIMITS = {
  max_url_chars: 2_048,
  max_redirects: 5,
  max_response_bytes: 200_000,
  per_operation_ms: 3_000,
  total_ms: 8_000,
} as const;

export interface SafeFetchEvidence {
  requested_url: string;
  final_url: string;
  redirect_chain: string[];
  validated_hops: { hostname: string; address_count: number }[];
}

export type SafeFetchResult =
  | { ok: true; html: string; evidence: SafeFetchEvidence }
  | { ok: false; reason: UnscannableReason; evidence: SafeFetchEvidence };

export interface SafeFetchSeams {
  fetcher?: Fetcher;
  resolver?: AddressResolver;
  dns?: WorkersDnsApi;
  now?: () => number;
  operation_ms?: number;
  total_ms?: number;
  record?: (entry: JournalEntry) => void;
}

export interface WorkersDnsApi {
  resolve4(hostname: string): Promise<readonly string[]>;
  resolve6(hostname: string): Promise<readonly string[]>;
}

const nativeWorkersDns: WorkersDnsApi = { resolve4, resolve6 };
const EMPTY_FAMILY_CODES = new Set(["ENODATA", "ENOTFOUND"]);

function dnsErrorCode(error: unknown): string | null {
  if (typeof error !== "object" || error === null || !("code" in error)) return null;
  return typeof error.code === "string" ? error.code : null;
}

async function resolveFamily(
  query: (hostname: string) => Promise<readonly string[]>,
  hostname: string,
  family: 4 | 6,
): Promise<readonly string[]> {
  let addresses: readonly string[];
  try { addresses = await query(hostname); }
  catch (error) {
    if (EMPTY_FAMILY_CODES.has(dnsErrorCode(error) ?? "")) return [];
    throw error;
  }
  if (addresses.some((address) => addressFamily(address) !== family)) {
    throw new TypeError("dns response invalid");
  }
  return addresses;
}

/** Cloudflare Workers' supported node:dns path; the signal bounds its caller. */
export function createWorkersDnsResolver(dns: WorkersDnsApi = nativeWorkersDns): AddressResolver {
  return async (hostname, signal) => {
    if (signal.aborted) throw new DOMException("aborted", "AbortError");
    const pending = Promise.all([
      resolveFamily(dns.resolve4.bind(dns), hostname, 4),
      resolveFamily(dns.resolve6.bind(dns), hostname, 6),
    ]).then(([v4, v6]) => [...v4, ...v6]);
    return new Promise((resolve, reject) => {
      let settled = false;
      const finish = (run: () => void) => {
        if (settled) return;
        settled = true;
        signal.removeEventListener("abort", abort);
        run();
      };
      const abort = () => finish(() => reject(new DOMException("aborted", "AbortError")));
      signal.addEventListener("abort", abort, { once: true });
      if (signal.aborted) abort();
      void pending.then(
        (addresses) => finish(() => resolve(addresses)),
        (error) => finish(() => reject(error)),
      );
    });
  };
}

async function operation<T>(
  run: (signal: AbortSignal) => Promise<T>,
  timeoutMs: number,
): Promise<T> {
  const controller = new AbortController();
  return new Promise((resolve, reject) => {
    let settled = false;
    const finish = (runFinish: () => void) => { if (!settled) { settled = true; clearTimeout(timer); runFinish(); } };
    let pending: Promise<T>;
    try { pending = run(controller.signal); } catch (error) { pending = Promise.reject(error); }
    void Promise.resolve(pending).then((value) => finish(() => resolve(value)), (error) => finish(() => reject(error)));
    const timer = setTimeout(() => finish(() => { controller.abort(); reject(new DOMException("timeout", "AbortError")); }), timeoutMs);
  });
}

function digest(bytes: Uint8Array): string {
  let value = 2_166_136_261;
  for (const byte of bytes) value = Math.imul(value ^ byte, 16_777_619) >>> 0;
  return value.toString(16).padStart(8, "0");
}

/**
 * Preflight-resolves every hop and relies on Cloudflare's connection-time
 * public-Internet fetch proxy as the second SSRF boundary. No DNS claim here
 * is represented as connection pinning; exact deployed probes remain required.
 */
export async function safeFetchHtml(
  rawUrl: string,
  seams: SafeFetchSeams = {},
): Promise<SafeFetchResult> {
  const fetcher = seams.fetcher ?? ((input, init) => fetch(input, init));
  const resolver = seams.resolver ?? createWorkersDnsResolver(seams.dns);
  const now = seams.now ?? Date.now;
  const started = now();
  const scope = createResponseScope(fetcher, now);
  const limits = { max_url_chars: SAFE_FETCH_LIMITS.max_url_chars, max_redirects: SAFE_FETCH_LIMITS.max_redirects, max_response_bytes: SAFE_FETCH_LIMITS.max_response_bytes, operation_ms: seams.operation_ms ?? SAFE_FETCH_LIMITS.per_operation_ms, total_ms: seams.total_ms ?? SAFE_FETCH_LIMITS.total_ms };
  let machine = createFetchMachine(rawUrl, limits, started);
  let active: ResponseHandle | undefined;
  let bound: { token: string; html: string; length: number; digest: string } | undefined;
  try {
    while (machine.pending !== null) {
      const effect = machine.pending;
      let fact: MachineFact;
      if (effect.kind === "dns") {
        let addresses: string[] = []; let failure: "timeout" | "network_error" | null = null;
        try {
          addresses = [...await operation((signal) => resolver(effect.hostname, signal), Math.max(0, effect.deadline! - effect.issued_at))];
        } catch (error) { failure = error instanceof DOMException && error.name === "AbortError" ? "timeout" : "network_error"; }
        const overflow = addresses.length > 32;
        fact = { kind: "dns", completed_at: now(), addresses: addresses.slice(0, 33), overflow, failure };
      } else if (effect.kind === "fetch") {
        const acquired = await scope.request(effect.url, { method: "GET", redirect: "manual", headers: { accept: "text/html", "accept-encoding": "identity" } }, effect.deadline!);
        if (acquired.ok) active = acquired.handle;
        fact = { kind: "fetch", completed_at: acquired.completed_at, failure: acquired.ok ? null : acquired.failure };
      } else if (effect.kind === "metadata") {
        const value = active === undefined ? { ok: false as const } : scope.metadata(active, effect.limits);
        if (value.ok) active = value.handle;
        fact = value.ok ? { kind: "metadata", completed_at: now(), status: value.status, headers: value.headers, failure: null } : { kind: "metadata", completed_at: now(), status: 0, headers: {}, failure: "invalid" };
      } else if (effect.kind === "discard") {
        if (active !== undefined) scope.discard(active);
        active = undefined; fact = { kind: "discard", completed_at: now() };
      } else {
        const value = active === undefined ? { ok: false as const, failure: "invalid" as const, completed_at: now() } : await scope.read(active, effect.maximum, effect.deadline!);
        active = undefined;
        let html = ""; let valid = value.ok;
        if (value.ok) { try { html = new TextDecoder("utf-8", { fatal: true }).decode(value.bytes); } catch { valid = false; } }
        const bodyDigest = value.ok ? digest(value.bytes) : "";
        if (value.ok && valid) bound = { token: effect.token, html, length: value.bytes.byteLength, digest: bodyDigest };
        fact = { kind: "read", completed_at: value.completed_at, failure: value.ok ? null : value.failure, token: effect.token, length: value.ok ? value.bytes.byteLength : 0, digest: bodyDigest, valid_utf8: valid };
      }
      const entry = journalEntry(effect, fact);
      seams.record?.(entry);
      machine = reduceFetchMachine(machine, fact);
    }
    const result = machine.terminal!;
    if (!result.ok) return result;
    if (bound === undefined || bound.token !== result.token || bound.length !== result.length || bound.digest !== result.digest) throw new TypeError("body binding mismatch");
    return { ok: true, html: bound.html, evidence: result.evidence };
  } finally {
    scope.seal();
  }
}
