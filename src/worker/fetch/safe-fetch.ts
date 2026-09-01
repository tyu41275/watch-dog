import {
  canonicalizeUrl,
  type UnscannableReason,
} from "../../shared/canonicalize.js";
import {
  admitPublicHost,
  type AddressResolver,
} from "./address.js";

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

type Fetcher = (input: string, init?: RequestInit) => Promise<Response>;

export interface SafeFetchSeams {
  fetcher?: Fetcher;
  resolver?: AddressResolver;
  now?: () => number;
  operation_ms?: number;
  total_ms?: number;
}

interface DnsJson {
  Status?: unknown;
  TC?: unknown;
  Answer?: unknown;
}

async function cancelBody(response: Response): Promise<void> {
  try { await response.body?.cancel(); } catch { /* best-effort release */ }
}

async function boundedBytes(
  response: Response,
  maximum: number,
  signal: AbortSignal,
): Promise<Uint8Array> {
  const declared = response.headers.get("content-length");
  if (declared !== null) {
    const length = Number(declared);
    if (!Number.isSafeInteger(length) || length < 0) {
      await cancelBody(response); throw new TypeError("invalid body length");
    }
    if (length > maximum) {
      await cancelBody(response); throw new RangeError("body limit exceeded");
    }
  }
  const reader = response.body?.getReader();
  if (reader === undefined) throw new TypeError("body unavailable");
  const abort = () => { void reader.cancel(); };
  signal.addEventListener("abort", abort, { once: true });
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    if (signal.aborted) throw new DOMException("aborted", "AbortError");
    while (true) {
      const { done, value } = await reader.read();
      if (signal.aborted) throw new DOMException("aborted", "AbortError");
      if (done) break;
      size += value.byteLength;
      if (size > maximum) { await reader.cancel(); throw new RangeError("body limit exceeded"); }
      chunks.push(value);
    }
    const bytes = new Uint8Array(size);
    let offset = 0;
    for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
    return bytes;
  } finally {
    signal.removeEventListener("abort", abort);
    reader.releaseLock();
  }
}

async function dnsQuery(
  hostname: string,
  type: "A" | "AAAA",
  signal: AbortSignal,
  fetcher: Fetcher,
): Promise<string[]> {
  const url = `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(hostname)}&type=${type}`;
  const response = await fetcher(url, {
    headers: { accept: "application/dns-json" },
    redirect: "error",
    signal,
  });
  if (!response.ok) {
    await cancelBody(response); throw new TypeError("dns response unavailable");
  }
  const bytes = await boundedBytes(response, SAFE_FETCH_LIMITS.max_dns_response_bytes, signal);
  const body = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)) as DnsJson;
  if (body.Status !== 0 || body.TC === true || !Array.isArray(body.Answer)) {
    if (body.Status === 0 && body.Answer === undefined) return [];
    throw new TypeError("dns response invalid");
  }
  if (body.Answer.length > 64) throw new TypeError("dns answer limit exceeded");
  const recordType = type === "A" ? 1 : 28;
  return body.Answer.flatMap((record) => {
    if (typeof record !== "object" || record === null) return [];
    const value = record as { type?: unknown; data?: unknown };
    return value.type === recordType && typeof value.data === "string" ? [value.data] : [];
  });
}

export function createCloudflareDohResolver(
  fetcher: Fetcher = (input, init) => fetch(input, init),
): AddressResolver {
  return async (hostname, signal) => {
    const scope = new AbortController();
    const abort = () => scope.abort();
    signal.addEventListener("abort", abort, { once: true });
    if (signal.aborted) scope.abort();
    try {
      const [v4, v6] = await Promise.all([
        dnsQuery(hostname, "A", scope.signal, fetcher),
        dnsQuery(hostname, "AAAA", scope.signal, fetcher),
      ]);
      return [...v4, ...v6];
    } finally {
      signal.removeEventListener("abort", abort);
      scope.abort();
    }
  };
}

export const cloudflareDohResolver = createCloudflareDohResolver();

function evidence(requestedUrl: string): SafeFetchEvidence {
  return { requested_url: requestedUrl, final_url: requestedUrl, redirect_chain: [], validated_hops: [] };
}

function failed(
  reason: UnscannableReason,
  value: SafeFetchEvidence,
): SafeFetchResult {
  return { ok: false, reason, evidence: value };
}

async function operation<T>(
  run: (signal: AbortSignal) => Promise<T>,
  timeoutMs: number,
): Promise<T> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await run(controller.signal);
  } finally {
    clearTimeout(timer);
  }
}

function remaining(started: number, now: () => number, operationMs: number, totalMs: number): number {
  return Math.min(
    operationMs,
    totalMs - (now() - started),
  );
}

type BoundedHtml =
  | { ok: true; html: string }
  | { ok: false; reason: UnscannableReason };

async function boundedHtml(response: Response, signal: AbortSignal): Promise<BoundedHtml> {
  const encoding = response.headers.get("content-encoding")?.trim().toLowerCase();
  if (encoding !== undefined && encoding !== "" && encoding !== "identity") {
    await cancelBody(response);
    return { ok: false, reason: "unsupported_content_encoding" };
  }
  const mediaType = response.headers.get("content-type")?.split(";", 1)[0]?.trim().toLowerCase();
  if (mediaType !== "text/html") {
    await cancelBody(response); return { ok: false, reason: "unsupported_content_type" };
  }
  try {
    const bytes = await boundedBytes(response, SAFE_FETCH_LIMITS.max_response_bytes, signal);
    return { ok: true, html: new TextDecoder("utf-8", { fatal: true }).decode(bytes) };
  } catch (error) {
    if (signal.aborted) throw error;
    return { ok: false, reason: error instanceof RangeError ? "response_too_large" : "invalid_response" };
  }
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
  const resolver = seams.resolver ?? cloudflareDohResolver;
  const now = seams.now ?? Date.now;
  const operationMs = seams.operation_ms ?? SAFE_FETCH_LIMITS.per_operation_ms;
  const totalMs = seams.total_ms ?? SAFE_FETCH_LIMITS.total_ms;
  const started = now();
  if (rawUrl.length > SAFE_FETCH_LIMITS.max_url_chars) {
    return failed("url_too_long", evidence(""));
  }
  const initial = canonicalizeUrl(rawUrl);
  const trace = evidence(initial.ok ? initial.target.canonical_url : "");
  if (!initial.ok) return failed(initial.reason, trace);
  if (initial.target.canonical_url.length > SAFE_FETCH_LIMITS.max_url_chars) {
    return failed("url_too_long", trace);
  }
  let current = initial.target.canonical_url;
  const visited = new Set<string>();

  for (let redirects = 0; ; redirects += 1) {
    if (visited.has(current)) return failed("redirect_loop", trace);
    visited.add(current);
    const timeout = remaining(started, now, operationMs, totalMs);
    if (timeout <= 0) return failed("timeout", trace);
    const parsed = new URL(current);
    let admission;
    try {
      admission = await operation(
        (signal) => admitPublicHost(parsed.hostname, resolver, signal),
        timeout,
      );
    } catch {
      return failed("timeout", trace);
    }
    if (!admission.ok) return failed(admission.reason, trace);
    trace.validated_hops.push({ hostname: admission.hostname, address_count: admission.addresses.length });

    let response: Response;
    try {
      const fetchTimeout = remaining(started, now, operationMs, totalMs);
      if (fetchTimeout <= 0) return failed("timeout", trace);
      response = await operation((signal) => fetcher(current, {
        method: "GET",
        redirect: "manual",
        headers: { accept: "text/html", "accept-encoding": "identity" },
        signal,
      }), fetchTimeout);
    } catch (error) {
      return failed(error instanceof DOMException && error.name === "AbortError" ? "timeout" : "fetch_failed", trace);
    }

    if (response.status >= 300 && response.status < 400) {
      await cancelBody(response);
      const location = response.headers.get("location");
      if (location === null) return failed("redirect_missing_location", trace);
      if (redirects >= SAFE_FETCH_LIMITS.max_redirects) return failed("redirect_limit", trace);
      const next = canonicalizeUrl(location, current);
      if (!next.ok) return failed(next.reason, trace);
      if (next.target.canonical_url.length > SAFE_FETCH_LIMITS.max_url_chars) {
        return failed("url_too_long", trace);
      }
      trace.redirect_chain.push(next.target.canonical_url);
      current = next.target.canonical_url;
      trace.final_url = current;
      continue;
    }
    if (response.status < 200 || response.status >= 300) {
      await cancelBody(response);
      return failed("invalid_response", trace);
    }
    const bodyTimeout = remaining(started, now, operationMs, totalMs);
    if (bodyTimeout <= 0) {
      await cancelBody(response); return failed("timeout", trace);
    }
    let bounded: BoundedHtml;
    try {
      bounded = await operation((signal) => boundedHtml(response, signal), bodyTimeout);
    } catch {
      return failed("timeout", trace);
    }
    return bounded.ok
      ? { ok: true, html: bounded.html, evidence: { ...trace, final_url: current } }
      : failed(bounded.reason, trace);
  }
}
