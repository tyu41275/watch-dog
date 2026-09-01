import { sessionClientFor } from "./session-client.js";

export const WEBMCP_LIMITS = Object.freeze({
  maxCandidates: 32,
  maxHrefChars: 2048,
  maxAnchorTextChars: 512,
});
const record = (value) => typeof value === "object" && value !== null && !Array.isArray(value);
const exact = (value, keys) => record(value) && Object.keys(value).sort().join() === [...keys].sort().join();
const consented = (pageDocument) => pageDocument.querySelector?.("#provider-consent")?.checked === true;

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

export function inspectCurrentPage(pageDocument, options = {}) {
  if (pageDocument?.pageDocument) {
    options = pageDocument; pageDocument = options.pageDocument;
    options.consent = options.consent ?? consented(pageDocument);
  }
  const observedAt = new Date().toISOString(); const extraction = extractRenderedPage(pageDocument, observedAt);
  return sessionClientFor(pageDocument, options.fetcher).scanLive({ document_url: pageDocument.URL,
    observed_at: observedAt, ...extraction }, options);
}

export function createInspectCurrentPageTool(pageDocument, fetcher) {
  return {
    name: "inspect_current_page", title: "Inspect this Watch Dog reference page",
    description: "Read the current rendered anchors on this fixed Watch Dog-owned reference page and analyze them as untrusted evidence. This does not inspect unrelated tabs or navigate.",
    inputSchema: { type: "object", properties: {}, additionalProperties: false },
    annotations: { readOnlyHint: true, untrustedContentHint: true },
    async execute(args = {}, context = {}) {
      if (!exact(args, [])) throw new Error("invalid_arguments");
      return JSON.stringify(await inspectCurrentPage(pageDocument, { fetcher, signal: context.signal,
        consent: consented(pageDocument) }));
    },
  };
}

export function createSupportingTools(fetcher, pageDocument) {
  const client = sessionClientFor(pageDocument, fetcher);
  return [{
    name: "scan_url", title: "Scan a URL or pasted HTML",
    description: "Analyze one HTTP(S) target. Optional pasted HTML is parsed locally without loading subresources.",
    inputSchema: { type: "object", required: ["targetUrl"], additionalProperties: false,
      properties: { targetUrl: { type: "string", maxLength: 2048 },
        pastedHtml: { type: "string", maxLength: 200000 }, baseUrl: { type: "string", maxLength: 2048 } } },
    annotations: { readOnlyHint: true, untrustedContentHint: true },
    async execute(args = {}, context = {}) {
      if (!record(args) || typeof args.targetUrl !== "string" || Object.keys(args).some((key) =>
        !["targetUrl", "pastedHtml", "baseUrl"].includes(key)) || args.targetUrl.length > 2048 ||
        args.pastedHtml?.length > 200000 || args.baseUrl?.length > 2048) throw new Error("invalid_arguments");
      const payload = args.pastedHtml === undefined ? { mode: "url", url: args.targetUrl } :
        { mode: "html", html: args.pastedHtml, base_url: args.baseUrl ?? args.targetUrl };
      return JSON.stringify(await client.scanPaste(payload, { signal: context.signal,
        consent: consented(pageDocument) }));
    },
  }, {
    name: "get_scan_result", title: "Get a Watch Dog scan result",
    description: "Retrieve one bounded ephemeral result owned by this authenticated session.",
    inputSchema: { type: "object", required: ["scanId"], additionalProperties: false,
      properties: { scanId: { type: "string", pattern: "^[a-f0-9]{32}$" } } },
    annotations: { readOnlyHint: true, untrustedContentHint: true },
    async execute(args = {}, context = {}) {
      if (!exact(args, ["scanId"]) || typeof args.scanId !== "string" ||
        !/^[a-f0-9]{32}$/u.test(args.scanId)) throw new Error("invalid_arguments");
      return JSON.stringify(await client.getResult(args.scanId, { signal: context.signal }));
    },
  }];
}

const renderStatus = (pageDocument, message) => {
  const status = pageDocument.querySelector("#webmcp-status"); if (status) status.textContent = message;
};
export async function registerBrowserTool() {
  if (document.modelContext === undefined) {
    renderStatus(document, "WebMCP is unavailable in this browser; the reference page remains inspectable by people.");
    return null;
  }
  const controller = new AbortController(); const fetcher = globalThis.fetch.bind(globalThis);
  const tools = [createInspectCurrentPageTool(document, fetcher), ...createSupportingTools(fetcher, document)];
  try { for (const tool of tools) await document.modelContext.registerTool(tool, { signal: controller.signal }); }
  catch (error) { controller.abort(); throw error; }
  renderStatus(document, "WebMCP tools registered: inspect_current_page, scan_url, get_scan_result."); return controller;
}
if (typeof document !== "undefined" && new URL(document.URL).pathname === "/reference") {
  void registerBrowserTool().catch(() =>
    renderStatus(document, "WebMCP registration failed; no tool is being claimed as available."));
}
