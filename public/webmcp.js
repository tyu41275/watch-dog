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
    const response = await fetcher(resource, init);
    if (!(response instanceof Response)) throw new Error("service_unavailable");
    return response;
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
    value.authenticated === true && typeof value.csrf_token === "string" &&
    /^[A-Za-z0-9_-]{32}$/u.test(value.csrf_token) &&
    typeof value.expires_at === "string" && Number.isFinite(Date.parse(value.expires_at)) &&
    new Date(value.expires_at).toISOString() === value.expires_at;
}

async function authenticatedPost(fetcher, path, payload, signal, providerConsent = false) {
  const session = await safeFetch(fetcher, "/api/session", {
    method: "GET", credentials: "same-origin", headers: { accept: "application/json" }, signal,
  });
  const sessionBody = await jsonResponse(session);
  if (!session.ok) throw typedError(session.status, sessionBody);
  if (!validSession(sessionBody)) throw new Error("malformed_response");
  signal?.throwIfAborted();
  const response = await safeFetch(fetcher, path, {
    method: "POST", credentials: "same-origin", signal,
    headers: {
      accept: "application/json", "content-type": "application/json",
      "x-watchdog-csrf": sessionBody.csrf_token,
      ...(providerConsent ? { "x-watchdog-provider-consent": "google_safe_browsing" } : {}),
    },
    body: JSON.stringify(payload),
  });
  const body = await jsonResponse(response);
  if (!response.ok) throw typedError(response.status, body);
  return body;
}

const REJECTION_REASONS = new Set([
  "empty_input", "missing_base_url", "invalid_url", "unsupported_scheme",
  "credentials_not_allowed", "disallowed_port", "url_too_long", "unsafe_address",
  "dns_failure", "mixed_address", "redirect_missing_location", "redirect_loop",
  "redirect_limit", "timeout", "response_too_large", "unsupported_content_type",
  "unsupported_content_encoding", "fetch_failed", "invalid_response", "input_too_large",
  "no_candidates",
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
    value.scan_ids.length > 16 || !value.scan_ids.every((id) =>
      typeof id === "string" && /^[a-f0-9]{32}$/u.test(id)) ||
    !Array.isArray(value.targets) || value.targets.length > 16 ||
    !Array.isArray(value.rejections) || value.rejections.length > 16
  ) return false;
  const validTarget = (target) => isRecord(target) && exactKeys(target, [
    "anchor_text_variants", "canonical_url", "occurrence_indices",
  ]) && validCanonicalTarget(target.canonical_url) &&
    Array.isArray(target.occurrence_indices) && target.occurrence_indices.length > 0 &&
    target.occurrence_indices.every((index) => integer(index) && index < WEBMCP_LIMITS.maxCandidates) &&
    Array.isArray(target.anchor_text_variants) &&
    target.anchor_text_variants.length <= target.occurrence_indices.length &&
    target.anchor_text_variants.every((text) =>
      typeof text === "string" && text !== "" && text === text.trim() &&
      text.length <= WEBMCP_LIMITS.maxAnchorTextChars) &&
    new Set(target.anchor_text_variants).size === target.anchor_text_variants.length;
  const validRejection = (rejection) => isRecord(rejection) &&
    exactKeys(rejection, ["occurrence_index", "reason"]) &&
    integer(rejection.occurrence_index) && rejection.occurrence_index < WEBMCP_LIMITS.maxCandidates &&
    REJECTION_REASONS.has(rejection.reason);
  if (!value.targets.every(validTarget) || !value.rejections.every(validRejection)) return false;
  const resultCount = Math.max(1, value.accepted_targets + value.rejected_candidates);
  const occurrenceIndices = [
    ...value.targets.flatMap((target) => target.occurrence_indices ?? []),
    ...value.rejections.map((rejection) => rejection.occurrence_index),
  ];
  const completeSummaries = value.targets.length === value.accepted_targets &&
    value.rejections.length === value.rejected_candidates;
  return new Set(value.scan_ids).size === value.scan_ids.length &&
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

export async function inspectCurrentPage({ pageDocument, fetcher, signal, providerConsent = false }) {
  signal?.throwIfAborted();
  const observedAt = new Date().toISOString();
  const extraction = extractRenderedPage(pageDocument, observedAt);
  const body = await authenticatedPost(fetcher, "/api/scans/live", {
    document_url: pageDocument.URL,
    observed_at: observedAt,
    ...extraction,
  }, signal, providerConsent);
  if (!validReceipt(body)) throw new Error("malformed_response");
  return JSON.stringify(body);
}

function validPasteReceipt(value) {
  const integer = (item) => Number.isSafeInteger(item) && item >= 0;
  const evidence = value?.fetch_evidence;
  const validFetch = evidence === null || (isRecord(evidence) && exactKeys(evidence,
    ["final_url", "redirect_chain", "requested_url", "validated_hops"]) &&
    validCanonicalTarget(evidence.requested_url) && validCanonicalTarget(evidence.final_url) &&
    Array.isArray(evidence.redirect_chain) && evidence.redirect_chain.length <= 5 &&
    evidence.redirect_chain.every(validCanonicalTarget) && Array.isArray(evidence.validated_hops) &&
    evidence.validated_hops.length <= 6 && evidence.validated_hops.every((hop) => isRecord(hop) &&
      exactKeys(hop, ["address_count", "hostname"]) && typeof hop.hostname === "string" &&
      hop.hostname.length <= 253 && integer(hop.address_count) && hop.address_count <= 128));
  const count = Math.max(1, (value?.accepted_targets ?? 0) + (value?.rejected_candidates ?? 0));
  return isRecord(value) && exactKeys(value, ["accepted_targets", "fetch_evidence", "mode",
    "rejected_candidates", "scan_ids", "truncated", "unscannable_reason"]) &&
    ["paste_url", "paste_html"].includes(value.mode) &&
    Array.isArray(value.scan_ids) && value.scan_ids.length <= 16 &&
    value.scan_ids.every((id) => typeof id === "string" && /^[a-f0-9]{32}$/u.test(id)) &&
    new Set(value.scan_ids).size === value.scan_ids.length && integer(value.accepted_targets) &&
    integer(value.rejected_candidates) && value.scan_ids.length === Math.min(count, 16) &&
    value.truncated === (count > 16) &&
    (value.unscannable_reason === null || REJECTION_REASONS.has(value.unscannable_reason)) &&
    validFetch && (value.mode === "paste_url" || evidence === null);
}

export async function scanUrl({ fetcher, targetUrl, pastedHtml, baseUrl, signal, providerConsent = false }) {
  signal?.throwIfAborted();
  if (typeof targetUrl !== "string" || targetUrl.length === 0 || targetUrl.length > 2048 ||
    (pastedHtml !== undefined && (typeof pastedHtml !== "string" || pastedHtml.length > 200_000)) ||
    (baseUrl !== undefined && (typeof baseUrl !== "string" || baseUrl.length > 2048))) {
    throw new Error("invalid_arguments");
  }
  const payload = pastedHtml === undefined
    ? { mode: "url", url: targetUrl }
    : { mode: "html", html: pastedHtml, base_url: baseUrl ?? targetUrl };
  const body = await authenticatedPost(fetcher, "/api/scans/paste", payload, signal, providerConsent);
  if (!validPasteReceipt(body)) throw new Error("malformed_response");
  return JSON.stringify(body);
}

export async function getScanResult({ fetcher, scanId, signal }) {
  signal?.throwIfAborted();
  if (typeof scanId !== "string" || !/^[a-f0-9]{32}$/u.test(scanId)) {
    throw new Error("invalid_arguments");
  }
  const response = await safeFetch(fetcher, `/api/results/${scanId}`, {
    method: "GET", credentials: "same-origin", headers: { accept: "application/json" }, signal,
  });
  const body = await jsonResponse(response);
  if (!response.ok) throw typedError(response.status, body);
  if (!isRecord(body) || !exactKeys(body, ["result", "status"]) || body.status !== "ok" ||
    !validScanResult(body.result, scanId)) throw new Error("malformed_response");
  return JSON.stringify(body.result);
}

const RESULT_KEYS = ["analysis_state", "canonical_target", "confidence", "contradicting_evidence",
  "limitations", "mode", "provider_observations", "risk_label", "scan_id", "supporting_evidence"];
const literals = (value, allowed) => typeof value === "string" && allowed.includes(value);
const bounded = (value, maximum = 2048) => typeof value === "string" && value.length <= maximum;
const timestamp = (value, nullable = false) => (nullable && value === null) ||
  (bounded(value, 32) && Number.isFinite(Date.parse(value)) && new Date(value).toISOString() === value);
function validScanResult(value, scanId) {
  const evidence = (item) => isRecord(item) && exactKeys(item,
    ["category", "freshness", "observed_at", "reference", "source", "target"]) &&
    bounded(item.source, 128) && bounded(item.target) && bounded(item.category, 512) &&
    timestamp(item.observed_at) && literals(item.freshness, ["fresh", "stale", "unknown"]) &&
    (item.reference === null || bounded(item.reference));
  const provider = (item) => isRecord(item) && exactKeys(item, ["category", "confidence", "error",
    "expires_at", "freshness", "observed_at", "provider", "queried_target", "reference", "source", "state"]) &&
    item.provider === "google_safe_browsing" && literals(item.source, ["live", "fixture"]) &&
    validCanonicalTarget(item.queried_target) && timestamp(item.observed_at) && timestamp(item.expires_at, true) &&
    literals(item.freshness, ["fresh", "stale", "unknown"]) &&
    literals(item.state, ["match", "no_match", "error", "not_configured"]) &&
    (item.category === null || bounded(item.category, 512)) && literals(item.confidence, ["high", "medium", "low"]) &&
    (item.reference === null || bounded(item.reference)) && (item.error === null || literals(item.error,
      ["timeout", "quota", "unavailable", "malformed_response", "not_configured"]));
  const array = (items, check) => Array.isArray(items) && items.length <= 16 && items.every(check);
  return isRecord(value) && exactKeys(value, RESULT_KEYS) && value.scan_id === scanId &&
    literals(value.mode, ["paste_url", "paste_html", "live_page"]) &&
    (value.canonical_target === null || validCanonicalTarget(value.canonical_target)) &&
    literals(value.risk_label, ["known_malicious", "suspicious", "no_known_match", "unknown"]) &&
    literals(value.analysis_state, ["complete", "unknown", "unscannable", "provider_error", "stale", "conflicting"]) &&
    literals(value.confidence, ["high", "medium", "low"]) && array(value.supporting_evidence, evidence) &&
    array(value.contradicting_evidence, evidence) && array(value.provider_observations, provider) &&
    array(value.limitations, (item) => bounded(item, 512));
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
      if (!consented(pageDocument)) throw new Error("provider_consent_required");
      const output = await inspectCurrentPage({
        pageDocument, fetcher, signal: context.signal, providerConsent: true,
      });
      const Event = pageDocument.defaultView?.CustomEvent;
      if (typeof pageDocument.dispatchEvent === "function" && typeof Event === "function") {
        pageDocument.dispatchEvent(new Event("watchdog:scan-receipt", { detail: JSON.parse(output) }));
      }
      return output;
    },
  };
}

function dispatch(pageDocument, type, detail) {
  const Event = pageDocument?.defaultView?.CustomEvent;
  if (typeof pageDocument?.dispatchEvent === "function" && typeof Event === "function") {
    pageDocument.dispatchEvent(new Event(type, { detail }));
  }
}

function consented(pageDocument) {
  return pageDocument?.querySelector?.("#provider-consent")?.checked === true;
}

export function createSupportingTools(fetcher, pageDocument) {
  return [
    {
      name: "scan_url", title: "Scan a URL or pasted HTML",
      description: "Analyze one HTTP(S) target through Watch Dog. Optional pasted HTML is parsed locally without loading subresources.",
      inputSchema: {
        type: "object", required: ["targetUrl"], additionalProperties: false,
        properties: {
          targetUrl: { type: "string", maxLength: 2048, description: "HTTP(S) target or effective fallback base URL." },
          pastedHtml: { type: "string", maxLength: 200000, description: "Optional inert HTML; selecting it disables network page fetch." },
          baseUrl: { type: "string", maxLength: 2048, description: "Optional effective base URL for pasted HTML." },
        },
      },
      annotations: { readOnlyHint: true, untrustedContentHint: true },
      async execute(args = {}, context = {}) {
        if (!isRecord(args) || Object.keys(args).some((key) =>
          !["targetUrl", "pastedHtml", "baseUrl"].includes(key))) throw new Error("invalid_arguments");
        if (!consented(pageDocument)) throw new Error("provider_consent_required");
        const output = await scanUrl({ fetcher, ...args, signal: context.signal, providerConsent: true });
        dispatch(pageDocument, "watchdog:scan-receipt", JSON.parse(output));
        return output;
      },
    },
    {
      name: "get_scan_result", title: "Get a Watch Dog scan result",
      description: "Retrieve one bounded ephemeral result owned by this authenticated session.",
      inputSchema: {
        type: "object", required: ["scanId"], additionalProperties: false,
        properties: { scanId: { type: "string", pattern: "^[a-f0-9]{32}$", description: "Opaque session-owned scan identifier." } },
      },
      annotations: { readOnlyHint: true, untrustedContentHint: true },
      async execute(args = {}, context = {}) {
        if (!isRecord(args) || !exactKeys(args, ["scanId"])) throw new Error("invalid_arguments");
        const output = await getScanResult({ fetcher, scanId: args.scanId, signal: context.signal });
        dispatch(pageDocument, "watchdog:scan-result", JSON.parse(output));
        return output;
      },
    },
  ];
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
  const fetcher = globalThis.fetch.bind(globalThis);
  const tools = [createInspectCurrentPageTool(document, fetcher), ...createSupportingTools(fetcher, document)];
  try {
    for (const tool of tools) await document.modelContext.registerTool(tool, { signal: controller.signal });
  } catch (error) {
    controller.abort();
    throw error;
  }
  renderStatus(document, "WebMCP tools registered: inspect_current_page, scan_url, get_scan_result.");
  return controller;
}

if (typeof document !== "undefined") {
  void registerBrowserTool().catch(() => {
    renderStatus(document, "WebMCP registration failed; no tool is being claimed as available.");
  });
}
