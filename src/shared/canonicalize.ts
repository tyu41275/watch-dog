export const CANONICAL_REJECTION_REASONS = [
  "empty_input",
  "missing_base_url",
  "invalid_url",
  "unsupported_scheme",
  "credentials_not_allowed",
  "disallowed_port",
] as const;

export type CanonicalRejectionReason =
  (typeof CANONICAL_REJECTION_REASONS)[number];

export interface CanonicalTarget {
  canonical_url: string;
  scheme: "http" | "https";
  hostname_ascii: string;
  display_hostname: string;
}

export type CanonicalizationResult =
  | { ok: true; target: CanonicalTarget }
  | { ok: false; reason: CanonicalRejectionReason };

const ABSOLUTE_SCHEME = /^[A-Za-z][A-Za-z\d+.-]*:/;

/**
 * Resolve and normalize a link with the runtime's WHATWG URL implementation.
 * The ASCII host is deliberately also used for display: showing a decoded IDN
 * would re-introduce Unicode-confusable hostnames at the trust boundary.
 */
export function canonicalizeUrl(
  rawHref: string,
  baseUrl?: string,
): CanonicalizationResult {
  if (rawHref.trim() === "") return { ok: false, reason: "empty_input" };

  let parsed: URL;
  try {
    try {
      parsed = new URL(rawHref);
    } catch {
      if (ABSOLUTE_SCHEME.test(rawHref.trimStart())) {
        return { ok: false, reason: "invalid_url" };
      }
      if (baseUrl === undefined || baseUrl.trim() === "") {
        return { ok: false, reason: "missing_base_url" };
      }
      const base = new URL(baseUrl);
      if (base.protocol !== "http:" && base.protocol !== "https:") {
        return { ok: false, reason: "invalid_url" };
      }
      parsed = new URL(rawHref, base);
    }
  } catch {
    return { ok: false, reason: "invalid_url" };
  }

  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    return { ok: false, reason: "unsupported_scheme" };
  }
  if (parsed.username !== "" || parsed.password !== "") {
    return { ok: false, reason: "credentials_not_allowed" };
  }
  // WHATWG URL already removes an explicitly supplied default port.
  if (parsed.port !== "") return { ok: false, reason: "disallowed_port" };

  parsed.hash = "";
  const scheme = parsed.protocol === "https:" ? "https" : "http";
  const hostnameAscii = parsed.hostname.toLowerCase();

  return {
    ok: true,
    target: {
      canonical_url: parsed.href,
      scheme,
      hostname_ascii: hostnameAscii,
      display_hostname: hostnameAscii,
    },
  };
}
