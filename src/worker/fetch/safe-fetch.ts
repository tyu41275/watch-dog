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
  max_dns_response_bytes: 16_384,
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
  now?: () => number;
  operation_ms?: number;
  total_ms?: number;
  record?: (entry: JournalEntry) => void;
}

interface DnsJson {
  Status?: unknown;
  TC?: unknown;
  Answer?: unknown;
}

async function dnsQuery(
  hostname: string,
  type: "A" | "AAAA",
  scope: ReturnType<typeof createResponseScope>,
  deadline: number,
): Promise<string[]> {
  const url = `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(hostname)}&type=${type}`;
  const acquired = await scope.request(url, {
    headers: { accept: "application/dns-json" },
    redirect: "error",
  }, deadline);
  if (!acquired.ok) throw new DOMException(acquired.failure, acquired.failure === "timeout" || acquired.failure === "sealed" ? "AbortError" : "NetworkError");
  const metadata = scope.metadata(acquired.handle, { "content-type": 256, "content-encoding": 128, "content-length": 32 });
  if (!metadata.ok) throw new TypeError("dns response unavailable");
  const mediaType = metadata.headers["content-type"]?.value?.split(";", 1)[0]?.trim().toLowerCase();
  const encoding = metadata.headers["content-encoding"]?.value?.trim().toLowerCase();
  const declared = metadata.headers["content-length"];
  const declaredSize = declared?.value === null || declared?.value === undefined ? null : Number(declared.value);
  if (metadata.status < 200 || metadata.status >= 300 || mediaType !== "application/dns-json" || metadata.headers["content-type"]?.overflow || metadata.headers["content-encoding"]?.overflow || declared?.overflow || (declaredSize !== null && (!Number.isSafeInteger(declaredSize) || declaredSize < 0)) || (encoding !== undefined && encoding !== "" && encoding !== "identity")) { scope.discard(metadata.handle); throw new TypeError("dns response unavailable"); }
  if (declaredSize !== null && declaredSize > SAFE_FETCH_LIMITS.max_dns_response_bytes) { scope.discard(metadata.handle); throw new RangeError("body limit exceeded"); }
  const read = await scope.read(metadata.handle, SAFE_FETCH_LIMITS.max_dns_response_bytes, deadline);
  if (!read.ok) throw read.failure === "limit" ? new RangeError("body limit exceeded") : new DOMException(read.failure, read.failure === "timeout" ? "AbortError" : "DataError");
  const body = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(read.bytes)) as DnsJson;
  if (body.Status !== 0 || typeof body.TC !== "boolean" || body.TC || (body.Answer !== undefined && !Array.isArray(body.Answer))) throw new TypeError("dns response invalid");
  if (body.Answer === undefined) return [];
  if (body.Answer.length > 64) throw new TypeError("dns answer limit exceeded");
  const recordType = type === "A" ? 1 : 28;
  const addresses: string[] = []; for (const record of body.Answer) {
    const value = typeof record === "object" && record !== null ? record as { type?: unknown; data?: unknown } : null;
    if (value === null || !Number.isInteger(value.type) || typeof value.data !== "string") throw new TypeError("dns response invalid");
    const family = addressFamily(value.data);
    if ((value.type === 1 && family !== 4) || (value.type === 28 && family !== 6)) throw new TypeError("dns response invalid");
    if (value.type === recordType) addresses.push(value.data);
  }
  return addresses;
}

export function createCloudflareDohResolver(
  fetcher: Fetcher = (input, init) => fetch(input, init),
): AddressResolver {
  return async (hostname, signal) => {
    const scope = createResponseScope(fetcher);
    const abort = () => { scope.seal(); };
    signal.addEventListener("abort", abort, { once: true });
    if (signal.aborted) scope.seal();
    try {
      const [v4, v6] = await Promise.all([
        dnsQuery(hostname, "A", scope, Number.POSITIVE_INFINITY),
        dnsQuery(hostname, "AAAA", scope, Number.POSITIVE_INFINITY),
      ]);
      if (v4.length + v6.length > 32) throw new TypeError("dns answer limit exceeded");
      return [...v4, ...v6];
    } finally {
      signal.removeEventListener("abort", abort);
      scope.seal();
    }
  };
}

export const cloudflareDohResolver = createCloudflareDohResolver();

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
          if (seams.resolver !== undefined) addresses = [...await operation((signal) => seams.resolver!(effect.hostname, signal), Math.max(0, effect.deadline! - effect.issued_at))];
          else {
            const values = await Promise.all([dnsQuery(effect.hostname, "A", scope, effect.deadline!), dnsQuery(effect.hostname, "AAAA", scope, effect.deadline!)]);
            addresses = [...values[0], ...values[1]];
          }
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
