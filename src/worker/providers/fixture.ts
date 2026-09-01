import type {
  ProviderErrorCode,
  ProviderObservation,
} from "../../shared/contracts.js";
import { canonicalizeUrl } from "../../shared/canonicalize.js";
import {
  PROVIDER_ADAPTER_LIMITS,
  RECOGNIZED_MALICIOUS_CATEGORIES,
  freshnessAt,
  timestamp,
  type ProviderAdapter,
  type ProviderRequest,
  type RecognizedMaliciousCategory,
} from "./types.js";

interface FixtureResult {
  observed_at: string;
  expires_at: string | null;
  reference?: string | null;
}

export type FixtureProviderScenario =
  | (FixtureResult & {
      outcome: "match";
      category: RecognizedMaliciousCategory;
    })
  | (FixtureResult & { outcome: "no_match" })
  | { outcome: "timeout" }
  | { outcome: "quota" }
  | { outcome: "unavailable" }
  | { outcome: "malformed_response" }
  | { outcome: "not_configured" };

function validateRequest(request: ProviderRequest): void {
  timestamp(request.requested_at, "requested_at");
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
}

function errorObservation(
  request: ProviderRequest,
  error: ProviderErrorCode,
): ProviderObservation {
  return {
    provider: "google_safe_browsing",
    source: "fixture",
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

/** Explicitly test-only normalization adapter. It performs no network access. */
export class FixtureProviderAdapter implements ProviderAdapter {
  readonly provider = "google_safe_browsing" as const;
  readonly source = "fixture" as const;

  constructor(private readonly scenario: FixtureProviderScenario) {
    Object.freeze(this);
  }

  async observe(request: ProviderRequest): Promise<ProviderObservation> {
    validateRequest(request);
    try {
      const scenario = this.scenario;
      if (
        scenario.outcome === "timeout" ||
        scenario.outcome === "quota" ||
        scenario.outcome === "unavailable" ||
        scenario.outcome === "malformed_response" ||
        scenario.outcome === "not_configured"
      ) {
        return errorObservation(request, scenario.outcome);
      }
      if (scenario.outcome !== "match" && scenario.outcome !== "no_match") {
        return errorObservation(request, "malformed_response");
      }

      if (typeof scenario.observed_at !== "string") throw new TypeError("invalid observed_at");
      const observed = timestamp(scenario.observed_at, "observed_at");
      const requested = timestamp(request.requested_at, "requested_at");
      if (observed > requested) return errorObservation(request, "malformed_response");

      let expiresAt: string | null = null;
      if (scenario.expires_at !== null) {
        if (typeof scenario.expires_at !== "string") throw new TypeError("invalid expires_at");
        const expires = timestamp(scenario.expires_at, "expires_at");
        if (expires < observed) return errorObservation(request, "malformed_response");
        expiresAt = new Date(expires).toISOString();
      }
      const reference = scenario.reference ?? null;
      if (
        reference !== null &&
        (typeof reference !== "string" ||
          reference.length > PROVIDER_ADAPTER_LIMITS.max_reference_chars)
      ) {
        return errorObservation(request, "malformed_response");
      }
      if (
        scenario.outcome === "match" &&
        (typeof scenario.category !== "string" ||
          !RECOGNIZED_MALICIOUS_CATEGORIES.includes(scenario.category) ||
          scenario.category.length > PROVIDER_ADAPTER_LIMITS.max_category_chars)
      ) {
        return errorObservation(request, "malformed_response");
      }

      const observedAt = new Date(observed).toISOString();
      const freshness = freshnessAt(observedAt, expiresAt, request.requested_at);
      return {
        provider: this.provider,
        source: this.source,
        queried_target: request.canonical_target,
        observed_at: observedAt,
        expires_at: expiresAt,
        freshness,
        state: scenario.outcome === "match" ? "match" : "no_match",
        category: scenario.outcome === "match" ? scenario.category : null,
        confidence: freshness === "fresh" ? "medium" : "low",
        reference,
        error: null,
      };
    } catch {
      return errorObservation(request, "malformed_response");
    }
  }
}
