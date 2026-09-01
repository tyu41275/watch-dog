import type {
  Freshness,
  ProviderErrorCode,
  ProviderId,
  ProviderObservation,
  ProviderSource,
} from "../../shared/contracts.js";
import { canonicalizeUrl } from "../../shared/canonicalize.js";

export const PROVIDER_ADAPTER_LIMITS = {
  max_target_chars: 2_048,
  max_category_chars: 128,
  max_reference_chars: 2_048,
} as const;

export const RECOGNIZED_MALICIOUS_CATEGORIES = [
  "malware",
  "social_engineering",
  "unwanted_software",
  "potentially_harmful_application",
] as const;

export type RecognizedMaliciousCategory =
  (typeof RECOGNIZED_MALICIOUS_CATEGORIES)[number];

export interface ProviderRequest {
  canonical_target: string;
  requested_at: string;
}

/** A provider normalizes one bounded lookup. It never owns an aggregate verdict. */
export interface ProviderAdapter {
  readonly provider: ProviderId;
  readonly source: ProviderSource;
  observe(request: ProviderRequest): Promise<ProviderObservation>;
}

export function timestamp(value: string, field: string): number {
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed)) throw new TypeError(`${field} must be a timestamp`);
  return parsed;
}

export function validateProviderRequest(request: ProviderRequest): number {
  const requested = timestamp(request.requested_at, "requested_at");
  if (
    request.canonical_target.length === 0 ||
    request.canonical_target.length > PROVIDER_ADAPTER_LIMITS.max_target_chars
  ) {
    throw new TypeError("canonical_target exceeds provider adapter limits");
  }
  const canonical = canonicalizeUrl(request.canonical_target);
  if (!canonical.ok || canonical.target.canonical_url !== request.canonical_target) {
    throw new TypeError("canonical_target must already be canonical HTTP(S)");
  }
  return requested;
}

export function providerErrorObservation(
  request: ProviderRequest,
  source: ProviderSource,
  error: ProviderErrorCode,
): ProviderObservation {
  return {
    provider: "google_safe_browsing",
    source,
    queried_target: request.canonical_target,
    observed_at: new Date(timestamp(request.requested_at, "requested_at")).toISOString(),
    expires_at: null,
    freshness: "unknown",
    state: error === "not_configured" ? "not_configured" : "error",
    category: null,
    confidence: "low",
    reference: null,
    error,
  };
}

export function freshnessAt(
  observedAt: string,
  expiresAt: string | null,
  evaluatedAt: string,
): Freshness {
  timestamp(observedAt, "observed_at");
  const evaluated = timestamp(evaluatedAt, "evaluated_at");
  if (expiresAt === null) return "unknown";
  return timestamp(expiresAt, "expires_at") <= evaluated ? "stale" : "fresh";
}
