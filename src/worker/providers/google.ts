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

async function boundedBytes(response: Response, signal: AbortSignal): Promise<Uint8Array> {
  const contentType = response.headers.get("content-type")?.split(";", 1)[0]?.trim().toLowerCase();
  if (contentType !== "application/json" && contentType !== "application/x-protobuf") {
    discardBody(response);
    throw new TypeError("provider response has an unsupported content type");
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
  return bytes;
}

interface ProtoCursor {
  offset: number;
}

function protoVarint(bytes: Uint8Array, cursor: ProtoCursor, end = bytes.length): number {
  let value = 0;
  let multiplier = 1;
  for (let count = 0; count < 10; count += 1) {
    if (cursor.offset >= end) throw new TypeError("truncated protobuf varint");
    const octet = bytes[cursor.offset] as number;
    cursor.offset += 1;
    const payload = octet & 0x7f;
    if (payload > Math.floor((Number.MAX_SAFE_INTEGER - value) / multiplier)) {
      throw new TypeError("protobuf integer exceeds bounds");
    }
    value += payload * multiplier;
    if ((octet & 0x80) === 0) {
      if (count > 0 && payload === 0) throw new TypeError("non-canonical protobuf varint");
      return value;
    }
    multiplier *= 128;
  }
  throw new TypeError("protobuf varint exceeds bounds");
}

function protoLength(bytes: Uint8Array, cursor: ProtoCursor, end: number): Uint8Array {
  const length = protoVarint(bytes, cursor, end);
  if (length > end - cursor.offset) throw new TypeError("truncated protobuf field");
  const value = bytes.subarray(cursor.offset, cursor.offset + length);
  cursor.offset += length;
  return value;
}

function protoKey(bytes: Uint8Array, cursor: ProtoCursor, end: number): [number, number] {
  const key = protoVarint(bytes, cursor, end);
  const field = Math.floor(key / 8);
  const wire = key % 8;
  if (field < 1 || field > 536_870_911) throw new TypeError("invalid protobuf field");
  return [field, wire];
}

function protoDuration(bytes: Uint8Array): string {
  const cursor = { offset: 0 };
  let seconds = 0;
  let nanos = 0;
  let hasSeconds = false;
  let hasNanos = false;
  while (cursor.offset < bytes.length) {
    const [field, wire] = protoKey(bytes, cursor, bytes.length);
    if (wire !== 0 || (field !== 1 && field !== 2)) {
      throw new TypeError("unsupported protobuf duration field");
    }
    const value = protoVarint(bytes, cursor);
    if (field === 1) {
      if (hasSeconds) throw new TypeError("duplicate protobuf duration seconds");
      seconds = value;
      hasSeconds = true;
    } else {
      if (hasNanos || value > 999_999_999) throw new TypeError("invalid protobuf duration nanos");
      nanos = value;
      hasNanos = true;
    }
  }
  return nanos === 0
    ? `${seconds}s`
    : `${seconds}.${String(nanos).padStart(9, "0")}s`;
}

function protoThreat(bytes: Uint8Array): Record<string, unknown> {
  const cursor = { offset: 0 };
  let url: string | undefined;
  const threatTypes: string[] = [];
  const names = [
    undefined,
    "MALWARE",
    "SOCIAL_ENGINEERING",
    "UNWANTED_SOFTWARE",
    "POTENTIALLY_HARMFUL_APPLICATION",
  ] as const;
  const addType = (value: number): void => {
    const name = names[value];
    if (name === undefined || threatTypes.length >= CATEGORY_PRIORITY.length) {
      throw new TypeError("unknown or excessive protobuf threat type");
    }
    threatTypes.push(name);
  };
  while (cursor.offset < bytes.length) {
    const [field, wire] = protoKey(bytes, cursor, bytes.length);
    if (field === 1 && wire === 2) {
      if (url !== undefined) throw new TypeError("duplicate protobuf threat URL");
      url = new TextDecoder("utf-8", { fatal: true })
        .decode(protoLength(bytes, cursor, bytes.length));
    } else if (field === 2 && wire === 0) {
      addType(protoVarint(bytes, cursor));
    } else if (field === 2 && wire === 2) {
      const packed = protoLength(bytes, cursor, bytes.length);
      const packedCursor = { offset: 0 };
      while (packedCursor.offset < packed.length) addType(protoVarint(packed, packedCursor));
    } else {
      throw new TypeError("unsupported protobuf threat field");
    }
  }
  if (url === undefined || threatTypes.length === 0) {
    throw new TypeError("incomplete protobuf threat");
  }
  return { url, threatTypes };
}

function protobufResponse(bytes: Uint8Array): unknown {
  const cursor = { offset: 0 };
  const threats: Record<string, unknown>[] = [];
  let cacheDuration: string | undefined;
  while (cursor.offset < bytes.length) {
    const [field, wire] = protoKey(bytes, cursor, bytes.length);
    if (wire !== 2 || (field !== 1 && field !== 2)) {
      throw new TypeError("unsupported protobuf response field");
    }
    const value = protoLength(bytes, cursor, bytes.length);
    if (field === 1) {
      if (threats.length >= GOOGLE_SAFE_BROWSING.max_threats) {
        throw new TypeError("excessive protobuf threats");
      }
      threats.push(protoThreat(value));
    } else {
      if (cacheDuration !== undefined) throw new TypeError("duplicate protobuf cache duration");
      cacheDuration = protoDuration(value);
    }
  }
  if (cacheDuration === undefined) throw new TypeError("missing protobuf cache duration");
  return threats.length === 0 ? { cacheDuration } : { threats, cacheDuration };
}

async function boundedProviderResponse(response: Response, signal: AbortSignal): Promise<unknown> {
  const contentType = response.headers.get("content-type")?.split(";", 1)[0]?.trim().toLowerCase();
  const bytes = await boundedBytes(response, signal);
  return contentType === "application/json"
    ? JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes))
    : protobufResponse(bytes);
}

function expressionUrl(value: string): URL {
  let decoded = encodeURI((value.split("#", 1)[0] ?? "").replace(/[\t\r\n]/gu, ""));
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
    for (let count = 1; count < 4; count += 1) {
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
    endpoint.searchParams.set("alt", "proto");
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
          headers: { accept: "application/x-protobuf", "x-goog-api-key": this.apiKey },
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
          await boundedProviderResponse(response, controller.signal), request, requestedMs,
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
