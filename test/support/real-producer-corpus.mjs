import { aggregateAnalysis } from "../../dist/shared/analysis.js";
import { collectLinkCandidates } from "../../dist/shared/candidates.js";
import { executePasteScan } from "../../dist/worker/fetch/paste.js";
import { executeLiveScan, parseLiveRequest } from "../../dist/worker/live.js";
import { FixtureProviderAdapter } from "../../dist/worker/providers/fixture.js";
import { CoordinatorCore, THROTTLE_ATTEMPTS } from "../../dist/worker/coordinator.js";

const NOW = "2026-09-01T06:30:00.000Z";
const OBSERVED = "2026-09-01T06:00:00.000Z";
const EXPIRES = "2026-09-01T07:00:00.000Z";
const REFERENCE = "https://watch.example/reference";
const SESSION = "s".repeat(32);
const clone = (value) => structuredClone(value);

function candidate(rawHref, anchorText, occurrenceIndex, source = "live_page", document = REFERENCE) {
  return { raw_href: rawHref, anchor_text: anchorText, base_url: document, provenance: { source, document_url: document, occurrence_index: occurrenceIndex, extracted_at: NOW } };
}

function deterministicUuid(index) {
  return `00000000-0000-4000-8000-${index.toString(16).padStart(12, "0")}`;
}

function installUuidSeam() {
  const own = Object.getOwnPropertyDescriptor(crypto, "randomUUID");
  let index = 0;
  Object.defineProperty(crypto, "randomUUID", { configurable: true, value: () => deterministicUuid(++index) });
  return () => own === undefined ? delete crypto.randomUUID : Object.defineProperty(crypto, "randomUUID", own);
}

function fixture(outcome, reference) {
  return new FixtureProviderAdapter({ outcome, ...(outcome === "match" ? { category: "social_engineering" } : {}), observed_at: OBSERVED, expires_at: EXPIRES, reference });
}

function recordingProvider(adapter, requests, operation) {
  return { provider: adapter.provider, source: adapter.source, observe: async (request) => { requests.push({ operation, request: clone(request) }); return adapter.observe(request); } };
}

function operationStore(core, events, operation) {
  return async (submitted) => {
    const scanId = core.putResult(SESSION, submitted, Date.parse(NOW));
    const lookup = core.getResult(SESSION, scanId, Date.parse(NOW));
    if (lookup.status !== "ok") throw new Error("coordinator did not retain submitted result");
    events.push({ operation, submitted: clone(submitted), scan_id: scanId, stored: clone(lookup.result) });
    return scanId;
  };
}

function liveRequest(count, duplicate = false) {
  const candidates = Array.from({ length: count }, (_, index) => candidate(
    duplicate && index < 2 ? `/duplicate#${index}` : `/live-${count}-${index}`,
    duplicate && index < 2 ? ["First label", "Second label"][index] : `Live ${index}`,
    index,
  ));
  const request = { document_url: REFERENCE, observed_at: NOW, candidates, extraction_rejections: [] };
  const parsed = parseLiveRequest(request, "https://watch.example", Date.parse(NOW));
  if (parsed === null) throw new Error(`real live parser rejected ${count} candidates`);
  return parsed;
}

export async function captureRealProducerCorpus() {
  const restoreUuid = installUuidSeam();
  try {
    const core = new CoordinatorCore();
    const events = { provider_requests: [], fetch_requests: [], resolutions: [], stores: [], throttle: [] };
    const contexts = {};
    const providerRequest = { canonical_target: "https://target.example/path", requested_at: NOW };
    const matchAdapter = fixture("match", "https://provider.example/match");
    const noMatchAdapter = fixture("no_match", "https://provider.example/no-match");
    events.provider_requests.push({ operation: "provider_match", request: clone(providerRequest) }, { operation: "provider_no_match", request: clone(providerRequest) });
    const [match, noMatch] = await Promise.all([matchAdapter.observe(providerRequest), noMatchAdapter.observe(providerRequest)]);
    contexts.provider = { requested_at: NOW, request: clone(providerRequest) };

    const analysisCandidates = [
      candidate("https://target.example/path#first", "https://display-z.example/login", 1, "paste_html", "https://source.example/one"),
      candidate("https://target.example/path#second", "https://display-a.example/login", 0, "live_page", "https://source.example/two"),
    ];
    const analysisTarget = collectLinkCandidates(analysisCandidates).targets[0];
    const analysisInput = { scan_id: "analysis_pending", mode: "live_page", analyzed_at: NOW, target: analysisTarget, provider_observations: [noMatch, match, match] };
    const analysis = aggregateAnalysis(analysisInput);
    contexts.analysis = { requested_at: NOW, facts: clone(analysisInput) };

    const resolver = async (hostname) => { events.resolutions.push(hostname); return ["93.184.216.34"]; };
    const successFetcher = async (url) => {
      events.fetch_requests.push(url);
      return new Response('<a href="/url-target#one">First</a><a href="/url-target#two">Second</a>', { headers: { "content-type": "text/html" } });
    };
    const pasteUrlRequest = { mode: "url", url: "https://public.example.co/page" };
    contexts.paste_url = { requested_at: NOW, request: clone(pasteUrlRequest) };
    const pasteUrl = await executePasteScan(pasteUrlRequest, { now: () => new Date(NOW), provider: recordingProvider(matchAdapter, events.provider_requests, "paste_url"), fetch_seams: { resolver, fetcher: successFetcher }, store: operationStore(core, events.stores, "paste_url") });

    const pasteHtmlRequest = { mode: "html", base_url: "https://source.example/base", html: '<a href="/same#one">First</a><a href="/same#two">Second</a><a href="mailto:x@y">Mail</a><a href="https://target.example/path">https://display.example/login</a>' };
    contexts.paste_html = { requested_at: NOW, request: clone(pasteHtmlRequest) };
    const pasteHtml = await executePasteScan(pasteHtmlRequest, { now: () => new Date(NOW), provider: recordingProvider(matchAdapter, events.provider_requests, "paste_html"), store: operationStore(core, events.stores, "paste_html") });

    const loopRequest = { mode: "url", url: "https://loop.example.co/a" };
    const loopFetcher = async (url) => { events.fetch_requests.push(url); return new Response(null, { status: 302, headers: { location: url.endsWith("/a") ? "/b" : "/a" } }); };
    contexts.redirect_loop = { requested_at: NOW, request: clone(loopRequest) };
    const redirectLoop = await executePasteScan(loopRequest, { now: () => new Date(NOW), fetch_seams: { resolver, fetcher: loopFetcher }, store: operationStore(core, events.stores, "redirect_loop") });

    const primaryLiveRequest = liveRequest(32, true);
    contexts.live = { requested_at: NOW, request: clone(primaryLiveRequest) };
    const live = await executeLiveScan(primaryLiveRequest, { now: () => new Date(NOW), provider: recordingProvider(matchAdapter, events.provider_requests, "live"), store: operationStore(core, events.stores, "live") });
    const liveBoundaries = {};
    for (const count of [0, 1, 15, 16, 17, 32]) liveBoundaries[count] = await executeLiveScan(liveRequest(count), { now: () => new Date(NOW), store: operationStore(core, events.stores, `live_boundary_${count}`) });

    const anchors = Array.from({ length: 257 }, (_, index) => `<a href="/paste-${index}">P${index}</a>`).join("");
    const paste256Request = { mode: "html", base_url: "https://source.example/base", html: anchors };
    contexts.paste_256 = { requested_at: NOW, request: clone(paste256Request) };
    const paste256 = await executePasteScan(paste256Request, { now: () => new Date(NOW), store: operationStore(core, events.stores, "paste_256") });

    contexts.coordinator = { requested_at: NOW, throttle_key: "corpus", session_id: SESSION };
    for (let attempt = 0; attempt <= THROTTLE_ATTEMPTS; attempt += 1) events.throttle.push(core.attemptLogin("corpus", Date.parse(NOW) + attempt));
    core.resetLogin("corpus");
    events.throttle.push(core.attemptLogin("corpus", Date.parse(NOW)));
    const pairs = events.stores.map(({ operation, scan_id, stored }) => ({ operation, receipt_id: scan_id, result_id: stored.scan_id }));
    return clone({ contexts, facts: { analysis_target: analysisTarget, live_request: primaryLiveRequest }, events, outputs: { provider: { match, no_match: noMatch }, analysis, paste_url: pasteUrl, paste_html: pasteHtml, redirect_loop: redirectLoop, live, live_boundaries: liveBoundaries, paste_256: paste256, coordinator: { pairs } } });
  } finally {
    restoreUuid();
  }
}
