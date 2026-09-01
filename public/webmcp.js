export const WEBMCP_LIMITS = Object.freeze({
  maxCandidates: 32,
  maxHrefChars: 2048,
  maxAnchorTextChars: 512,
});

export function extractRenderedPage(pageDocument, observedAt = new Date().toISOString()) {
  const anchors = Array.from(pageDocument.querySelectorAll("a[href]"));
  const candidates = [];
  const extractionRejections = [];
  for (const anchor of anchors.slice(0, WEBMCP_LIMITS.maxCandidates)) {
    const rawHref = anchor.getAttribute("href");
    if (rawHref === null) continue;
    const occurrenceIndex = candidates.length + extractionRejections.length;
    if (rawHref.length > WEBMCP_LIMITS.maxHrefChars) {
      extractionRejections.push({ occurrence_index: occurrenceIndex, reason: "url_too_long" });
      continue;
    }
    const anchorText = String(anchor.textContent ?? "")
      .replace(/\s+/gu, " ")
      .trim()
      .slice(0, WEBMCP_LIMITS.maxAnchorTextChars);
    candidates.push({
      raw_href: rawHref,
      anchor_text: anchorText,
      base_url: pageDocument.baseURI,
      provenance: {
        source: "live_page",
        document_url: pageDocument.URL,
        occurrence_index: occurrenceIndex,
        extracted_at: observedAt,
      },
    });
  }
  return { candidates, extraction_rejections: extractionRejections };
}

function typedError(status, body) {
  if (status === 401 || status === 403) return new Error("unauthorized");
  if (status === 400) return new Error("invalid_request");
  if (body?.error === "scan_unavailable") return new Error("scan_unavailable");
  if (body?.error === "malformed_response") return new Error("malformed_response");
  return new Error("service_unavailable");
}

async function jsonResponse(response) {
  try {
    return await response.json();
  } catch (error) {
    if (error?.name === "AbortError") throw error;
    return null;
  }
}

async function safeFetch(fetcher, resource, init) {
  try {
    return await fetcher(resource, init);
  } catch (error) {
    if (error?.name === "AbortError") throw error;
    throw new Error("service_unavailable");
  }
}

function isRecord(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function exactKeys(value, expected) {
  const keys = Object.keys(value).sort();
  return keys.length === expected.length && keys.every((key, index) => key === expected[index]);
}

function validSession(value) {
  return isRecord(value) && exactKeys(value, ["authenticated", "csrf_token", "expires_at"]) &&
    value.authenticated === true && /^[A-Za-z0-9_-]{32}$/u.test(value.csrf_token) &&
    typeof value.expires_at === "string" && Number.isFinite(Date.parse(value.expires_at)) &&
    new Date(value.expires_at).toISOString() === value.expires_at;
}

const REJECTION_REASONS = new Set([
  "empty_input", "missing_base_url", "invalid_url", "unsupported_scheme",
  "credentials_not_allowed", "disallowed_port", "url_too_long",
]);

function validCanonicalTarget(value) {
  if (typeof value !== "string" || value.length > 2048) return false;
  try {
    const parsed = new URL(value);
    return (parsed.protocol === "http:" || parsed.protocol === "https:") &&
      parsed.username === "" && parsed.password === "" && parsed.port === "" &&
      parsed.hash === "" && parsed.href === value;
  } catch {
    return false;
  }
}

function validReceipt(value) {
  if (!isRecord(value) || !exactKeys(value, [
    "accepted_targets", "mode", "observed_candidates", "page_evidence_trust",
    "rejected_candidates", "rejections", "scan_ids", "targets", "truncated",
  ])) return false;
  const integer = (item) => Number.isSafeInteger(item) && item >= 0;
  if (
    value.mode !== "live_page" || value.page_evidence_trust !== "untrusted" ||
    !integer(value.observed_candidates) || value.observed_candidates > WEBMCP_LIMITS.maxCandidates ||
    !integer(value.accepted_targets) || !integer(value.rejected_candidates) ||
    typeof value.truncated !== "boolean" || !Array.isArray(value.scan_ids) ||
    value.scan_ids.length > 16 || !value.scan_ids.every((id) => /^[a-f0-9]{32}$/u.test(id)) ||
    !Array.isArray(value.targets) || value.targets.length > 16 ||
    !Array.isArray(value.rejections) || value.rejections.length > 16
  ) return false;
  const validTarget = (target) => isRecord(target) && exactKeys(target, [
    "anchor_text_variants", "canonical_url", "occurrence_indices",
  ]) && validCanonicalTarget(target.canonical_url) &&
    Array.isArray(target.occurrence_indices) && target.occurrence_indices.every((index) =>
      integer(index) && index < WEBMCP_LIMITS.maxCandidates) &&
    Array.isArray(target.anchor_text_variants) && target.anchor_text_variants.every((text) =>
      typeof text === "string" && text.length <= WEBMCP_LIMITS.maxAnchorTextChars);
  const validRejection = (rejection) => isRecord(rejection) &&
    exactKeys(rejection, ["occurrence_index", "reason"]) &&
    integer(rejection.occurrence_index) && rejection.occurrence_index < WEBMCP_LIMITS.maxCandidates &&
    REJECTION_REASONS.has(rejection.reason);
  const resultCount = Math.max(1, value.accepted_targets + value.rejected_candidates);
  const occurrenceIndices = [
    ...value.targets.flatMap((target) => target.occurrence_indices ?? []),
    ...value.rejections.map((rejection) => rejection.occurrence_index),
  ];
  const completeSummaries = value.targets.length === value.accepted_targets &&
    value.rejections.length === value.rejected_candidates;
  return value.targets.every(validTarget) && value.rejections.every(validRejection) &&
    new Set(value.scan_ids).size === value.scan_ids.length &&
    new Set(value.targets.map(({ canonical_url: url }) => url)).size === value.targets.length &&
    new Set(occurrenceIndices).size === occurrenceIndices.length &&
    value.accepted_targets + value.rejected_candidates <= value.observed_candidates &&
    value.targets.length === Math.min(value.accepted_targets, 16) &&
    value.rejections.length === Math.min(value.rejected_candidates, 16) &&
    value.scan_ids.length === Math.min(resultCount, 16) &&
    value.truncated === (resultCount > 16) && (!completeSummaries || (
      occurrenceIndices.length === value.observed_candidates &&
      [...occurrenceIndices].sort((left, right) => left - right)
        .every((index, position) => index === position)
    ));
}

export async function inspectCurrentPage({ pageDocument, fetcher, signal }) {
  signal?.throwIfAborted();
  const observedAt = new Date().toISOString();
  const extraction = extractRenderedPage(pageDocument, observedAt);
  const session = await safeFetch(fetcher, "/api/session", {
    method: "GET",
    credentials: "same-origin",
    headers: { accept: "application/json" },
    signal,
  });
  const sessionBody = await jsonResponse(session);
  if (!session.ok) throw typedError(session.status, sessionBody);
  if (!validSession(sessionBody)) throw new Error("malformed_response");
  signal?.throwIfAborted();
  const response = await safeFetch(fetcher, "/api/scans/live", {
    method: "POST",
    credentials: "same-origin",
    headers: {
      accept: "application/json",
      "content-type": "application/json",
      "x-watchdog-csrf": sessionBody.csrf_token,
    },
    body: JSON.stringify({
      document_url: pageDocument.URL,
      observed_at: observedAt,
      ...extraction,
    }),
    signal,
  });
  const body = await jsonResponse(response);
  if (!response.ok) throw typedError(response.status, body);
  if (!validReceipt(body)) throw new Error("malformed_response");
  return JSON.stringify(body);
}

export function createInspectCurrentPageTool(pageDocument, fetcher) {
  return {
    name: "inspect_current_page",
    title: "Inspect this Watch Dog reference page",
    description: "Read the current rendered anchors on this fixed Watch Dog-owned reference page and analyze them as untrusted evidence. This does not inspect unrelated tabs or navigate.",
    inputSchema: {
      type: "object",
      properties: {},
      additionalProperties: false,
    },
    annotations: {
      readOnlyHint: true,
      untrustedContentHint: true,
    },
    async execute(argumentsObject = {}, context = {}) {
      if (
        typeof argumentsObject !== "object" || argumentsObject === null ||
        Array.isArray(argumentsObject) || Object.keys(argumentsObject).length !== 0
      ) throw new Error("invalid_arguments");
      return inspectCurrentPage({ pageDocument, fetcher, signal: context.signal });
    },
  };
}

function renderStatus(pageDocument, message) {
  const status = pageDocument.querySelector("#webmcp-status");
  if (status !== null) status.textContent = message;
}

export async function registerBrowserTool() {
  if (document.modelContext === undefined) {
    renderStatus(document, "WebMCP is unavailable in this browser; the reference page remains inspectable by people.");
    return null;
  }
  const controller = new AbortController();
  const tool = createInspectCurrentPageTool(document, globalThis.fetch.bind(globalThis));
  await document.modelContext.registerTool(tool, { signal: controller.signal });
  renderStatus(document, "WebMCP tool registered: inspect_current_page.");
  return controller;
}

if (typeof document !== "undefined") {
  void registerBrowserTool().catch(() => {
    renderStatus(document, "WebMCP registration failed; no tool is being claimed as available.");
  });
}
