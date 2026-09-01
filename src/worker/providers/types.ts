import type {
  Freshness,
  ProviderId,
  ProviderObservation,
} from "../../shared/contracts.js";

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
  readonly source: "live" | "fixture";
  observe(request: ProviderRequest): Promise<ProviderObservation>;
}

export function timestamp(value: string, field: string): number {
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed)) throw new TypeError(`${field} must be a timestamp`);
  return parsed;
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
