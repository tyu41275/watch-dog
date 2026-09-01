import assert from "node:assert/strict";
import test from "node:test";

import { parseProviderObservation } from "../dist/shared/contracts.js";
import { executePasteScan } from "../dist/worker/fetch/paste.js";
import { executeLiveScan } from "../dist/worker/live.js";
import {
  GOOGLE_SAFE_BROWSING,
  GoogleSafeBrowsingAdapter,
} from "../dist/worker/providers/google.js";

const canonicalTarget = "https://example.test/path?q=one&q=two";
const requestedAt = "2026-09-01T08:30:00.000Z";
const request = { canonical_target: canonicalTarget, requested_at: requestedAt };

function json(value, init = {}) {
  return Response.json(value, init);
}

function expectedError(error) {
  return {
    provider: "google_safe_browsing",
    source: "live",
    queried_target: canonicalTarget,
    observed_at: requestedAt,
    expires_at: null,
    freshness: "unknown",
    state: error === "not_configured" ? "not_configured" : "error",
    category: null,
    confidence: "low",
    reference: null,
    error,
  };
}

async function observeResponse(response, { key = "server-only-key", timeout_ms = 50 } = {}) {
  return new GoogleSafeBrowsingAdapter(key, {
    timeout_ms,
    fetcher: async () => response,
  }).observe(request);
}

test("missing configuration is live-source not_configured without attempting a request", async () => {
  let calls = 0;
  const adapter = new GoogleSafeBrowsingAdapter("  ", {
    fetcher: async () => {
      calls += 1;
      throw new Error("must not fetch");
    },
  });
  assert.deepEqual(await adapter.observe(request), expectedError("not_configured"));
  assert.equal(calls, 0);
  assert.equal(adapter.provider, "google_safe_browsing");
  assert.equal(adapter.source, "live");
  assert.equal(Reflect.set(adapter, "source", "fixture"), false);
});

test("v5 lookup sends one raw canonical URL and keeps the API key out of the URL and result", async () => {
  const secret = "secret-that-must-not-escape";
  const seen = [];
  const adapter = new GoogleSafeBrowsingAdapter(secret, {
    fetcher: async (input, init) => {
      const url = new URL(input);
      const headers = new Headers(init.headers);
      seen.push({ url, headers, init });
      return json({ cacheDuration: "60.25s" });
    },
  });
  const observation = parseProviderObservation(await adapter.observe(request));
  assert.equal(seen.length, 1);
  assert.equal(seen[0].url.origin + seen[0].url.pathname, GOOGLE_SAFE_BROWSING.endpoint);
  assert.deepEqual([...seen[0].url.searchParams.keys()], ["urls"]);
  assert.equal(seen[0].url.searchParams.get("urls"), canonicalTarget);
  assert.equal(seen[0].url.href.includes(secret), false);
  assert.equal(seen[0].headers.get("x-goog-api-key"), secret);
  assert.equal(seen[0].headers.get("accept"), "application/json");
  assert.equal(seen[0].init.method, "GET");
  assert.ok(seen[0].init.signal instanceof AbortSignal);
  assert.deepEqual(observation, {
    provider: "google_safe_browsing",
    source: "live",
    queried_target: canonicalTarget,
    observed_at: requestedAt,
    expires_at: "2026-09-01T08:31:00.250Z",
    freshness: "fresh",
    state: "no_match",
    category: null,
    confidence: "medium",
    reference: null,
    error: null,
  });
  assert.equal(JSON.stringify(observation).includes(secret), false);
  assert.doesNotMatch(JSON.stringify(observation), /\b(is safe|safe to|clean|harmless)\b/i);
});

test("recognized threats map to closed categories with Google-only attribution and 30-minute freshness", async () => {
  const cases = [
    ["MALWARE", "malware"],
    ["SOCIAL_ENGINEERING", "social_engineering"],
    ["UNWANTED_SOFTWARE", "unwanted_software"],
    ["POTENTIALLY_HARMFUL_APPLICATION", "potentially_harmful_application"],
  ];
  for (const [threatType, category] of cases) {
    const observation = parseProviderObservation(await observeResponse(json({
      threats: [{ url: canonicalTarget, threatTypes: [threatType] }],
      cacheDuration: "7200s",
    })));
    assert.equal(observation.state, "match", threatType);
    assert.equal(observation.category, category, threatType);
    assert.equal(observation.expires_at, "2026-09-01T09:00:00.000Z", threatType);
    assert.equal(observation.reference, GOOGLE_SAFE_BROWSING.advisory, threatType);
    assert.equal(observation.source, "live", threatType);
  }
  const priority = await observeResponse(json({
    threats: [{
      url: canonicalTarget,
      threatTypes: ["UNWANTED_SOFTWARE", "MALWARE", "SOCIAL_ENGINEERING"],
    }],
    cacheDuration: "1s",
  }));
  assert.equal(priority.category, "malware");
});

test("HTTP, network, timeout and invalid transport failures normalize without payload leakage", async () => {
  let cancellations = 0;
  const pending = (init) => new Response(new ReadableStream({
    cancel() { cancellations += 1; },
  }), init);
  assert.deepEqual(await observeResponse(pending({ status: 429 })),
    expectedError("quota"));
  assert.deepEqual(await observeResponse(pending({ status: 504 })),
    expectedError("timeout"));
  assert.deepEqual(await observeResponse(pending({ status: 503 })),
    expectedError("unavailable"));
  assert.deepEqual(await observeResponse(pending({ headers: { "content-type": "text/plain" } })),
    expectedError("malformed_response"));
  assert.deepEqual(await observeResponse(pending({ headers: {
    "content-type": "application/json",
    "content-length": String(GOOGLE_SAFE_BROWSING.max_response_bytes + 1),
  } })), expectedError("malformed_response"));
  assert.equal(cancellations, 5);
  const network = new GoogleSafeBrowsingAdapter("key", {
    fetcher: async () => { throw new TypeError("network detail secret"); },
  });
  assert.deepEqual(await network.observe(request), expectedError("unavailable"));
  const invalid = new GoogleSafeBrowsingAdapter("key", {
    fetcher: async () => ({ ok: true }),
  });
  assert.deepEqual(await invalid.observe(request), expectedError("unavailable"));
  const brokenBody = await observeResponse(new Response(new ReadableStream({
    start(controller) { controller.error(new TypeError("stream detail secret")); },
  }), { headers: { "content-type": "application/json" } }));
  assert.deepEqual(brokenBody, expectedError("unavailable"));
  const hanging = new GoogleSafeBrowsingAdapter("key", {
    timeout_ms: 1,
    fetcher: async (_input, init) => new Promise((_resolve, reject) => {
      init.signal.addEventListener("abort", () => reject(init.signal.reason), { once: true });
    }),
  });
  assert.deepEqual(await hanging.observe(request), expectedError("timeout"));

  let bodyCancelled = false;
  const hangingStream = new ReadableStream({
    cancel() { bodyCancelled = true; return new Promise(() => undefined); },
  });
  const hangingBody = new GoogleSafeBrowsingAdapter("key", {
    timeout_ms: 1,
    fetcher: async () => new Response(hangingStream,
      { headers: { "content-type": "application/json" } }),
  });
  assert.deepEqual(await hangingBody.observe(request), expectedError("timeout"));
  assert.equal(bodyCancelled, true);
  assert.equal(hangingStream.locked, false);
});

test("response parsing fails closed on malformed, oversized and open provider shapes",
  { timeout: 1_000 }, async () => {
  const validThreat = { url: canonicalTarget, threatTypes: ["MALWARE"] };
  const malformed = [
    new Response("not-json", { headers: { "content-type": "application/json" } }),
    new Response("{}", { headers: { "content-type": "text/plain" } }),
    json([]),
    json({ threats: [] }),
    json({ threats: [], cacheDuration: "1m" }),
    json({ threats: [], cacheDuration: "01s" }),
    json({ threats: null, cacheDuration: "1s" }),
    json({ threats: [], cacheDuration: "1s", rawPayload: "secret" }),
    json({ threats: [{ ...validThreat, rawPayload: "secret" }], cacheDuration: "1s" }),
    json({ threats: [{ url: "not a URL", threatTypes: ["MALWARE"] }], cacheDuration: "1s" }),
    json({ threats: [{ url: "https://different.test/", threatTypes: ["MALWARE"] }],
      cacheDuration: "1s" }),
    json({ threats: [{ url: canonicalTarget, threatTypes: [] }], cacheDuration: "1s" }),
    json({ threats: [{ url: canonicalTarget, threatTypes: ["UNKNOWN"] }], cacheDuration: "1s" }),
    ...["toString", "constructor", "__proto__"].map((type) =>
      json({ threats: [{ url: canonicalTarget, threatTypes: [type] }], cacheDuration: "1s" })),
    json({
      threats: Array(GOOGLE_SAFE_BROWSING.max_threats + 1).fill(validThreat),
      cacheDuration: "1s",
    }),
    new Response("x".repeat(GOOGLE_SAFE_BROWSING.max_response_bytes + 1), {
      headers: { "content-type": "application/json" },
    }),
    new Response("{}", {
      headers: {
        "content-type": "application/json",
        "content-length": String(GOOGLE_SAFE_BROWSING.max_response_bytes + 1),
      },
    }),
    new Response(new ReadableStream({
      pull(controller) {
        controller.enqueue(new Uint8Array(GOOGLE_SAFE_BROWSING.max_response_bytes + 1));
      },
      cancel() { return new Promise(() => undefined); },
    }), { headers: { "content-type": "application/json" } }),
  ];
  for (const response of malformed) {
    const observation = await observeResponse(response);
    assert.deepEqual(observation, expectedError("malformed_response"));
    assert.equal(JSON.stringify(observation).includes("secret"), false);
  }
  });

test("request and constructor bounds reject before provider I/O", async () => {
  assert.throws(() => new GoogleSafeBrowsingAdapter("key", { timeout_ms: 0 }),
    /invalid provider timeout/);
  assert.throws(() => new GoogleSafeBrowsingAdapter("key", { timeout_ms: 10_001 }),
    /invalid provider timeout/);
  const adapter = new GoogleSafeBrowsingAdapter("key", {
    fetcher: async () => { throw new Error("must not fetch invalid input"); },
  });
  await assert.rejects(adapter.observe({ ...request, canonical_target: "HTTPS://EXAMPLE.TEST/" }),
    /must already be canonical/);
  await assert.rejects(adapter.observe({ ...request, requested_at: "not-time" }),
    /must be a timestamp/);
});

function liveObservation(providerRequest) {
  return {
    provider: "google_safe_browsing",
    source: "live",
    queried_target: providerRequest.canonical_target,
    observed_at: providerRequest.requested_at,
    expires_at: new Date(Date.parse(providerRequest.requested_at) + 60_000).toISOString(),
    freshness: "fresh",
    state: "no_match",
    category: null,
    confidence: "medium",
    reference: null,
    error: null,
  };
}

test("Paste and Live inject the same normalized adapter only for accepted targets", async () => {
  const calls = [];
  const provider = Object.freeze({
    provider: "google_safe_browsing",
    source: "live",
    observe: async (providerRequest) => {
      calls.push(structuredClone(providerRequest));
      return liveObservation(providerRequest);
    },
  });
  const pasteStored = [];
  const paste = await executePasteScan({
    mode: "html",
    html: '<a href="./one">One</a><a href="mailto:no@example.test">No</a>',
    base_url: "https://example.test/base/",
  }, {
    now: () => new Date(requestedAt),
    provider,
    store: async (result) => {
      pasteStored.push(result);
      return String(pasteStored.length).padStart(32, "0");
    },
  });
  assert.equal(paste.accepted_targets, 1);
  assert.equal(paste.rejected_candidates, 1);
  assert.deepEqual(calls[0], {
    canonical_target: "https://example.test/base/one",
    requested_at: requestedAt,
  });
  assert.equal(pasteStored[0].provider_observations[0].source, "live");
  assert.equal(pasteStored[0].risk_label, "no_known_match");

  const liveStored = [];
  const live = await executeLiveScan({
    document_url: "https://watch.example/reference",
    observed_at: requestedAt,
    candidates: [{
      raw_href: "./two",
      anchor_text: "Two",
      base_url: "https://watch.example/reference",
      provenance: {
        source: "live_page",
        document_url: "https://watch.example/reference",
        occurrence_index: 0,
        extracted_at: requestedAt,
      },
    }],
    extraction_rejections: [],
  }, {
    now: () => new Date(requestedAt),
    provider,
    store: async (result) => {
      liveStored.push(result);
      return String(liveStored.length).padStart(32, "a");
    },
  });
  assert.equal(live.accepted_targets, 1);
  assert.deepEqual(calls[1], {
    canonical_target: "https://watch.example/two",
    requested_at: requestedAt,
  });
  assert.equal(liveStored[0].provider_observations[0].source, "live");
  assert.equal(liveStored[0].risk_label, "no_known_match");

  const beforeRejected = calls.length;
  await executePasteScan({
    mode: "html",
    html: '<a href="mailto:no@example.test">No</a>',
    base_url: "https://example.test/",
  }, { now: () => new Date(requestedAt), provider, store: async () => "f".repeat(32) });
  await executeLiveScan({
    document_url: "https://watch.example/reference",
    observed_at: requestedAt,
    candidates: [],
    extraction_rejections: [{ occurrence_index: 0, reason: "url_too_long" }],
  }, { now: () => new Date(requestedAt), provider, store: async () => "e".repeat(32) });
  assert.equal(calls.length, beforeRejected);
});

test("provider work is concurrent and capped to the retained result budget", async () => {
  let calls = 0;
  let release;
  const gate = new Promise((resolve) => { release = resolve; });
  const provider = Object.freeze({
    provider: "google_safe_browsing",
    source: "live",
    observe: async (providerRequest) => {
      calls += 1;
      await gate;
      return liveObservation(providerRequest);
    },
  });
  const html = Array.from({ length: 20 }, (_, index) =>
    `<a href="https://target-${index}.example/">${index}</a>`).join("");
  const pending = executePasteScan({ mode: "html", html, base_url: canonicalTarget }, {
    now: () => new Date(requestedAt),
    provider,
    store: async () => "d".repeat(32),
  });
  await new Promise((resolve) => setTimeout(resolve, 0));
  assert.equal(calls, 16);
  release();
  const receipt = await pending;
  assert.equal(receipt.accepted_targets, 20);
  assert.equal(receipt.scan_ids.length, 16);
  assert.equal(receipt.truncated, true);
});
