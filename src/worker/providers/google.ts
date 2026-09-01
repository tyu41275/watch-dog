import { getDomain } from "tldts";

import type { ProviderObservation } from "../../shared/contracts.js";
import {
  PROVIDER_ADAPTER_LIMITS,
  freshnessAt,
  providerErrorObservation,
  validateProviderRequest,
  type ProviderAdapter,
  type ProviderRequest,
  type RecognizedMaliciousCategory,
} from "./types.js";

export const GOOGLE_SAFE_BROWSING = {
  endpoint: "https://safebrowsing.googleapis.com/v5/urls:search",
  advisory: "https://transparencyreport.google.com/safe-browsing/search",
  max_response_bytes: 64_000,
  max_threats: 32,
  max_cache_ms: 30 * 60_000,
  timeout_ms: 2_500,
} as const;

const THREAT_CATEGORIES = {
  MALWARE: "malware",
  SOCIAL_ENGINEERING: "social_engineering",
  UNWANTED_SOFTWARE: "unwanted_software",
  POTENTIALLY_HARMFUL_APPLICATION: "potentially_harmful_application",
} as const satisfies Record<string, RecognizedMaliciousCategory>;

const CATEGORY_PRIORITY = [
  "MALWARE",
  "SOCIAL_ENGINEERING",
  "UNWANTED_SOFTWARE",
  "POTENTIALLY_HARMFUL_APPLICATION",
] as const;

interface GoogleSafeBrowsingDependencies {
  fetcher?: typeof fetch;
  timeout_ms?: number;
}

class ProviderTransportError extends Error {}

function discardBody(response: Response): void {
  if (response.body !== null) void response.body.cancel().catch(() => undefined);
}

function record(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function exactKeys(value: Record<string, unknown>, expected: string[]): boolean {
  const keys = Object.keys(value).sort();
  return keys.length === expected.length && keys.every((key, index) => key === expected[index]);
}

function durationMilliseconds(value: unknown): number | null {
  if (typeof value !== "string") return null;
  const match = /^(0|[1-9][0-9]*)(?:\.([0-9]{1,9}))?s$/u.exec(value);
  if (match === null) return null;
  const seconds = Number(match[1]);
  const fraction = Number(`0.${match[2] ?? "0"}`);
  const milliseconds = (seconds + fraction) * 1_000;
  return Number.isFinite(milliseconds) && milliseconds <= Number.MAX_SAFE_INTEGER
    ? Math.ceil(milliseconds)
    : null;
}

async function boundedJson(response: Response, signal: AbortSignal): Promise<unknown> {
  const contentType = response.headers.get("content-type")?.split(";", 1)[0]?.trim().toLowerCase();
  if (contentType !== "application/json") {
    discardBody(response);
    throw new TypeError("provider response is not JSON");
  }
  const declared = Number(response.headers.get("content-length") ?? 0);
  if (
    !Number.isSafeInteger(declared) || declared < 0 ||
    declared > GOOGLE_SAFE_BROWSING.max_response_bytes
  ) {
    discardBody(response);
    throw new TypeError("provider response exceeds bounds");
  }
  const reader = response.body?.getReader();
  if (reader === undefined) throw new TypeError("provider response has no body");
  const chunks: Uint8Array[] = [];
  let length = 0;
  let abort: (() => void) | undefined;
  const aborted = new Promise<never>((_resolve, reject) => {
    abort = () => {
      void reader.cancel(signal.reason).catch(() => undefined);
      reject(signal.reason instanceof Error
        ? signal.reason
        : new DOMException("provider request timed out", "AbortError"));
    };
    if (signal.aborted) abort();
    else signal.addEventListener("abort", abort, { once: true });
  });
  try {
    while (true) {
      let chunk: ReadableStreamReadResult<Uint8Array>;
      try {
        chunk = await Promise.race([reader.read(), aborted]);
      } catch (error) {
        if (signal.aborted) throw error;
        throw new ProviderTransportError();
      }
      const { done, value } = chunk;
      if (done) break;
      length += value.byteLength;
      if (length > GOOGLE_SAFE_BROWSING.max_response_bytes) {
        void reader.cancel().catch(() => undefined);
        throw new TypeError("provider response exceeds bounds");
      }
      chunks.push(value);
    }
  } finally {
    if (abort !== undefined) signal.removeEventListener("abort", abort);
    reader.releaseLock();
  }
  const bytes = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.length;
  }
  return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
}

function expressionUrl(value: string): URL {
  let decoded = (value.split("#", 1)[0] ?? "").replace(/[\t\r\n]/gu, "");
  while (/%[\da-f]{2}/iu.test(decoded)) decoded = decoded.replace(
    /%([\da-f]{2})/giu, (_match, octet: string) => String.fromCharCode(Number.parseInt(octet, 16)),
  );
  decoded = decoded.replace(/[^\x21-\x7e]|[#%]/gu, (character) =>
    `%${character.charCodeAt(0).toString(16).padStart(2, "0").toUpperCase()}`);
  const url = new URL(decoded);
  url.hash = "";
  url.pathname = url.pathname.replace(/\/{2,}/gu, "/");
  return url;
}

function expressionHost(hostname: string): string {
  hostname = hostname.replace(/^\.+|\.+$/gu, "").replace(/\.{2,}/gu, ".").toLowerCase();
  const mapped = /^\[(?:::ffff:|64:ff9b::)([\da-f]{1,4}):([\da-f]{1,4})\]$/iu.exec(hostname);
  if (mapped === null) return hostname;
  const high = Number.parseInt(mapped[1] ?? "", 16);
  const low = Number.parseInt(mapped[2] ?? "", 16);
  return [high >> 8, high & 255, low >> 8, low & 255].join(".");
}

function threatUrlMatches(value: unknown, canonicalTarget: string): boolean {
  if (typeof value !== "string" || value.length === 0 || value.length >
    PROVIDER_ADAPTER_LIMITS.max_target_chars) return false;
  try {
    const url = expressionUrl(value);
    const target = expressionUrl(canonicalTarget);
    const targetHost = expressionHost(target.hostname);
    const hosts = new Set([targetHost]);
    const registrable = getDomain(targetHost, { allowPrivateDomains: true });
    if (registrable !== null) {
      const labels = targetHost.split(".");
      const start = labels.length - registrable.split(".").length;
      for (let index = start; index >= Math.max(0, start - 3); index -= 1) {
        hosts.add(labels.slice(index).join("."));
      }
    }
    const paths = new Set([target.pathname + target.search, target.pathname, "/"]);
    let slash = 0;
    for (let count = 1; count <= 4; count += 1) {
      slash = target.pathname.indexOf("/", slash + 1);
      if (slash < 0) break;
      paths.add(target.pathname.slice(0, slash + 1));
    }
    return url.hostname !== "" && hosts.has(expressionHost(url.hostname)) &&
      paths.has(url.pathname + url.search);
  } catch {
    return false;
  }
}

function normalizedResponse(
  value: unknown,
  request: ProviderRequest,
  requestedMs: number,
): ProviderObservation | null {
  if (!record(value) ||
    (!exactKeys(value, ["cacheDuration"]) &&
      !exactKeys(value, ["cacheDuration", "threats"]))) {
    return null;
  }
  const threats = Object.hasOwn(value, "threats") ? value.threats : [];
  if (!Array.isArray(threats) || threats.length > GOOGLE_SAFE_BROWSING.max_threats) return null;
  const cacheMs = durationMilliseconds(value.cacheDuration);
  if (cacheMs === null) return null;
  const found = new Set<keyof typeof THREAT_CATEGORIES>();
  for (const threat of threats) {
    if (!record(threat) || !exactKeys(threat, ["threatTypes", "url"]) ||
      !threatUrlMatches(threat.url, request.canonical_target) ||
      !Array.isArray(threat.threatTypes) ||
      threat.threatTypes.length === 0 || threat.threatTypes.length > CATEGORY_PRIORITY.length) {
      return null;
    }
    for (const type of threat.threatTypes) {
      if (typeof type !== "string" || !Object.hasOwn(THREAT_CATEGORIES, type)) return null;
      found.add(type as keyof typeof THREAT_CATEGORIES);
    }
  }
  const observedAt = new Date(requestedMs).toISOString();
  const expiresAt = new Date(requestedMs + Math.min(cacheMs, GOOGLE_SAFE_BROWSING.max_cache_ms))
    .toISOString();
  const freshness = freshnessAt(observedAt, expiresAt, observedAt);
  const type = CATEGORY_PRIORITY.find((candidate) => found.has(candidate));
  return {
    provider: "google_safe_browsing",
    source: "live",
    queried_target: request.canonical_target,
    observed_at: observedAt,
    expires_at: expiresAt,
    freshness,
    state: type === undefined ? "no_match" : "match",
    category: type === undefined ? null : THREAT_CATEGORIES[type],
    confidence: freshness === "fresh" ? "medium" : "low",
    reference: type === undefined ? null : GOOGLE_SAFE_BROWSING.advisory,
    error: null,
  };
}

/** One bounded server-side v5 URL lookup. Raw provider payloads never leave this method. */
export class GoogleSafeBrowsingAdapter implements ProviderAdapter {
  readonly provider = "google_safe_browsing" as const;
  readonly source = "live" as const;
  private readonly apiKey: string | null;
  private readonly fetcher: typeof fetch;
  private readonly timeoutMs: number;

  constructor(apiKey: string | undefined, dependencies: GoogleSafeBrowsingDependencies = {}) {
    this.apiKey = apiKey?.trim() ? apiKey : null;
    this.fetcher = dependencies.fetcher ?? globalThis.fetch.bind(globalThis);
    this.timeoutMs = dependencies.timeout_ms ?? GOOGLE_SAFE_BROWSING.timeout_ms;
    if (!Number.isSafeInteger(this.timeoutMs) || this.timeoutMs < 1 || this.timeoutMs > 10_000) {
      throw new TypeError("invalid provider timeout");
    }
    Object.freeze(this);
  }

  async observe(request: ProviderRequest): Promise<ProviderObservation> {
    const requestedMs = validateProviderRequest(request);
    if (this.apiKey === null) {
      return providerErrorObservation(request, this.source, "not_configured");
    }
    const endpoint = new URL(GOOGLE_SAFE_BROWSING.endpoint);
    endpoint.searchParams.append("urls", request.canonical_target);
    const controller = new AbortController();
    let expire!: (reason: DOMException) => void;
    const expired = new Promise<never>((_resolve, reject) => { expire = reject; });
    const timeout = setTimeout(() => {
      const reason = new DOMException("provider request timed out", "AbortError");
      controller.abort(reason);
      expire(reason);
    }, this.timeoutMs);
    try {
      let response: Response;
      try {
        const transport = this.fetcher(endpoint, {
          method: "GET",
          headers: { accept: "application/json", "x-goog-api-key": this.apiKey },
          signal: controller.signal,
        });
        void transport.then((late) => {
          if (controller.signal.aborted && late instanceof Response) discardBody(late);
        }, () => undefined);
        response = await Promise.race([transport, expired]);
      } catch (error) {
        return providerErrorObservation(request, this.source,
          controller.signal.aborted || (error instanceof DOMException && error.name === "AbortError")
            ? "timeout"
            : "unavailable");
      }
      if (!(response instanceof Response)) {
        return providerErrorObservation(request, this.source, "unavailable");
      }
      if (response.status === 429) {
        discardBody(response);
        return providerErrorObservation(request, this.source, "quota");
      }
      if (response.status === 408 || response.status === 504) {
        discardBody(response);
        return providerErrorObservation(request, this.source, "timeout");
      }
      if (!response.ok) {
        discardBody(response);
        return providerErrorObservation(request, this.source, "unavailable");
      }
      try {
        const observation = normalizedResponse(
          await boundedJson(response, controller.signal), request, requestedMs,
        );
        return observation ?? providerErrorObservation(request, this.source, "malformed_response");
      } catch (error) {
        return providerErrorObservation(request, this.source,
          controller.signal.aborted || (error instanceof DOMException && error.name === "AbortError")
            ? "timeout"
            : error instanceof ProviderTransportError ? "unavailable" : "malformed_response");
      }
    } finally {
      clearTimeout(timeout);
    }
  }
}
