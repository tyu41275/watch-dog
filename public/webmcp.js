import { sessionClientFor } from "./session-client.js";

export const WEBMCP_LIMITS = Object.freeze({
  maxCandidates: 32,
  maxHrefChars: 2048,
  maxAnchorTextChars: 512,
  maxPastedHtmlChars: 200_000,
});

const toolAnnotations = Object.freeze({ readOnlyHint: true, untrustedContentHint: true });

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
      .replace(/\s+/gu, " ").trim().slice(0, WEBMCP_LIMITS.maxAnchorTextChars);
    candidates.push({
      raw_href: rawHref,
      anchor_text: anchorText,
      base_url: pageDocument.baseURI,
      provenance: { source: "live_page", document_url: pageDocument.URL,
        occurrence_index: occurrenceIndex, extracted_at: observedAt },
    });
  }
  return { candidates, extraction_rejections: extractionRejections };
}

function confirmProviderDisclosure(pageDocument) {
  const confirm = pageDocument.defaultView?.confirm;
  return typeof confirm === "function" && confirm.call(pageDocument.defaultView,
    "Watch Dog may send canonical target URLs to Google Safe Browsing for this scan. Continue?") === true;
}

function exactArguments(value, allowed) {
  return typeof value === "object" && value !== null && !Array.isArray(value) &&
    Object.keys(value).every((key) => allowed.includes(key));
}

function bounded(value, maximum, required = false) {
  return value === undefined ? !required : typeof value === "string" &&
    value.length >= (required ? 1 : 0) && value.length <= maximum;
}

function controllerFor(pageDocument, fetcher, controller) {
  return controller ?? sessionClientFor(pageDocument, fetcher);
}

export async function inspectCurrentPage({ pageDocument, fetcher, controller, signal }) {
  signal?.throwIfAborted();
  const observedAt = new Date().toISOString();
  const request = { document_url: pageDocument.URL, observed_at: observedAt,
    ...extractRenderedPage(pageDocument, observedAt) };
  const output = await controllerFor(pageDocument, fetcher, controller).scanLive(request, {
    consent: confirmProviderDisclosure(pageDocument), signal,
  });
  return JSON.stringify(output);
}

export function createInspectCurrentPageTool(pageDocument, fetcher, controller) {
  return {
    name: "inspect_current_page",
    title: "Inspect this Watch Dog reference page",
    description: "Read current rendered anchors on this fixed Watch Dog-owned reference page as untrusted evidence. This does not inspect unrelated tabs or navigate.",
    inputSchema: { type: "object", properties: {}, additionalProperties: false },
    annotations: toolAnnotations,
    async execute(argumentsObject = {}, context = {}) {
      if (!exactArguments(argumentsObject, []) || Object.keys(argumentsObject).length !== 0) {
        throw new Error("invalid_arguments");
      }
      return inspectCurrentPage({ pageDocument, fetcher, controller, signal: context.signal });
    },
  };
}

export function createSupportingTools(pageDocument, fetcher, controller) {
  const client = controllerFor(pageDocument, fetcher, controller);
  return [
    {
      name: "scan_url",
      title: "Scan a URL or inert pasted HTML",
      description: "Analyze one bounded URL, or bounded pasted HTML without executing it, through Watch Dog's shared evidence pipeline.",
      inputSchema: {
        type: "object",
        properties: {
          targetUrl: { type: "string", maxLength: WEBMCP_LIMITS.maxHrefChars },
          pastedHtml: { type: "string", maxLength: WEBMCP_LIMITS.maxPastedHtmlChars },
          baseUrl: { type: "string", maxLength: WEBMCP_LIMITS.maxHrefChars },
        },
        required: ["targetUrl"],
        additionalProperties: false,
      },
      annotations: toolAnnotations,
      async execute(argumentsObject = {}, context = {}) {
        if (!exactArguments(argumentsObject, ["targetUrl", "pastedHtml", "baseUrl"]) ||
          !bounded(argumentsObject.targetUrl, WEBMCP_LIMITS.maxHrefChars, true) ||
          !bounded(argumentsObject.pastedHtml, WEBMCP_LIMITS.maxPastedHtmlChars) ||
          !bounded(argumentsObject.baseUrl, WEBMCP_LIMITS.maxHrefChars) ||
          (argumentsObject.baseUrl !== undefined && argumentsObject.pastedHtml === undefined)) {
          throw new Error("invalid_arguments");
        }
        const payload = argumentsObject.pastedHtml === undefined
          ? { mode: "url", url: argumentsObject.targetUrl }
          : { mode: "html", html: argumentsObject.pastedHtml,
              base_url: argumentsObject.baseUrl ?? argumentsObject.targetUrl };
        return JSON.stringify(await client.scanPaste(payload, {
          consent: confirmProviderDisclosure(pageDocument), signal: context.signal,
        }));
      },
    },
    {
      name: "get_scan_result",
      title: "Get a session-owned scan result",
      description: "Retrieve one bounded opaque result owned by the current authenticated session.",
      inputSchema: {
        type: "object",
        properties: { scanId: { type: "string", pattern: "^[a-f0-9]{32}$" } },
        required: ["scanId"],
        additionalProperties: false,
      },
      annotations: toolAnnotations,
      async execute(argumentsObject = {}, context = {}) {
        if (!exactArguments(argumentsObject, ["scanId"]) ||
          typeof argumentsObject.scanId !== "string" ||
          !/^[a-f0-9]{32}$/u.test(argumentsObject.scanId)) {
          throw new Error("invalid_arguments");
        }
        return JSON.stringify(await client.getResult(argumentsObject.scanId,
          { signal: context.signal }));
      },
    },
  ];
}

function renderStatus(pageDocument, message) {
  const status = pageDocument.querySelector("#webmcp-status");
  if (status !== null) status.textContent = message;
}

export async function registerBrowserTools(pageDocument = document,
  fetcher = globalThis.fetch.bind(globalThis)) {
  if (pageDocument.modelContext === undefined) {
    renderStatus(pageDocument,
      "WebMCP is unavailable in this browser; this page remains inspectable by people.");
    return null;
  }
  const registration = new AbortController();
  const client = sessionClientFor(pageDocument, fetcher);
  const tools = [createInspectCurrentPageTool(pageDocument, fetcher, client),
    ...createSupportingTools(pageDocument, fetcher, client)];
  try {
    for (const tool of tools) {
      await pageDocument.modelContext.registerTool(tool, { signal: registration.signal });
    }
  } catch (error) {
    registration.abort(new DOMException("partial registration", "AbortError"));
    renderStatus(pageDocument, "WebMCP registration failed; no tools are claimed available.");
    throw error;
  }
  renderStatus(pageDocument,
    "WebMCP tools registered: inspect_current_page, scan_url, get_scan_result.");
  return registration;
}

export const registerBrowserTool = registerBrowserTools;

if (typeof document !== "undefined") {
  void registerBrowserTools().catch(() => {});
}
