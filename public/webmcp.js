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

function validSession(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value) &&
    Object.keys(value).sort().join() === "authenticated,csrf_token,expires_at" &&
    value.authenticated === true && typeof value.csrf_token === "string" &&
    /^[A-Za-z0-9_-]{32}$/u.test(value.csrf_token) &&
    typeof value.expires_at === "string" && Number.isFinite(Date.parse(value.expires_at)) &&
    new Date(value.expires_at).toISOString() === value.expires_at;
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
  const requestBody = {
    document_url: pageDocument.URL,
    observed_at: observedAt,
    ...extraction,
  };
  const response = await safeFetch(fetcher, "/api/scans/live", {
    method: "POST",
    credentials: "same-origin",
    headers: {
      accept: "application/json",
      "content-type": "application/json",
      "x-watchdog-csrf": sessionBody.csrf_token,
    },
    body: JSON.stringify(requestBody),
    signal,
  });
  const body = await jsonResponse(response);
  if (!response.ok) throw typedError(response.status, body);
  try {
    const exchange = await decodeLiveExchange({
      request: requestBody,
      receipt: body,
      loadResult: async (id) => {
        const result = await safeFetch(fetcher, `/api/results/${id}`, {
          method: "GET", credentials: "same-origin",
          headers: { accept: "application/json" }, signal,
        });
        const resultBody = await jsonResponse(result);
        if (!result.ok) throw typedError(result.status, resultBody);
        return resultBody;
      },
    });
    return JSON.stringify(presentExchange(exchange));
  } catch (error) {
    if (error?.message === "unauthorized") throw error;
    throw new Error("malformed_response");
  }
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
import { decodeLiveExchange, presentExchange } from "./results.js";
