export const WEBMCP_LIMITS = Object.freeze({
  maxCandidates: 32,
  maxHrefChars: 2048,
  maxAnchorTextChars: 512,
});

export function extractRenderedCandidates(pageDocument, observedAt = new Date().toISOString()) {
  const anchors = Array.from(pageDocument.querySelectorAll("a[href]"));
  const candidates = [];
  for (const anchor of anchors) {
    if (candidates.length >= WEBMCP_LIMITS.maxCandidates) break;
    const rawHref = anchor.getAttribute("href");
    if (rawHref === null || rawHref.length > WEBMCP_LIMITS.maxHrefChars) continue;
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
        occurrence_index: candidates.length,
        extracted_at: observedAt,
      },
    });
  }
  return candidates;
}

function typedError(status, body) {
  if (status === 401 || status === 403) return new Error("unauthorized");
  if (status === 400) return new Error("invalid_request");
  if (body?.error === "scan_unavailable") return new Error("scan_unavailable");
  return new Error("service_unavailable");
}

async function jsonResponse(response) {
  try {
    return await response.json();
  } catch {
    return null;
  }
}

export async function inspectCurrentPage({ pageDocument, fetcher, signal }) {
  signal?.throwIfAborted();
  const observedAt = new Date().toISOString();
  const candidates = extractRenderedCandidates(pageDocument, observedAt);
  const session = await fetcher("/api/session", {
    method: "GET",
    credentials: "same-origin",
    headers: { accept: "application/json" },
    signal,
  });
  const sessionBody = await jsonResponse(session);
  if (!session.ok || typeof sessionBody?.csrf_token !== "string") {
    throw typedError(session.status, sessionBody);
  }
  signal?.throwIfAborted();
  const response = await fetcher("/api/scans/live", {
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
      candidates,
    }),
    signal,
  });
  const body = await jsonResponse(response);
  if (!response.ok || body === null) throw typedError(response.status, body);
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
