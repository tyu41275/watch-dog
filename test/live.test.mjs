import assert from "node:assert/strict";
import test from "node:test";

import { createSession, readAuthSecrets } from "../dist/worker/auth.js";
import { SessionCoordinator } from "../dist/worker/coordinator.js";
import {
  LIVE_LIMITS,
  executeLiveScan,
  parseLiveRequest,
} from "../dist/worker/live.js";
import worker from "../dist/worker/index.js";
import {
  WEBMCP_LIMITS,
  createInspectCurrentPageTool,
  extractRenderedPage,
  inspectCurrentPage,
  registerBrowserTool,
} from "../public/webmcp.js";

class MemoryStorage {
  values = new Map();
  async get(key) { return structuredClone(this.values.get(key)); }
  async put(key, value) { this.values.set(key, structuredClone(value)); }
  async delete(key) { return this.values.delete(key); }
}

function configured() {
  const coordinator = new SessionCoordinator({ storage: new MemoryStorage() });
  return {
    ADMIN_USERNAME: "judge",
    ADMIN_PASSWORD: "correct horse battery staple",
    SESSION_SIGNING_KEY: "s".repeat(32),
    SESSION_COORDINATOR: {
      idFromName: (name) => name,
      get: () => coordinator,
    },
  };
}

function candidate(rawHref, text, index, observedAt, overrides = {}) {
  return {
    raw_href: rawHref,
    anchor_text: text,
    base_url: "https://watch.example/reference",
    provenance: {
      source: "live_page",
      document_url: "https://watch.example/reference",
      occurrence_index: index,
      extracted_at: observedAt,
    },
    ...overrides,
  };
}

function anchor(href, text) {
  return { getAttribute: (name) => name === "href" ? href : null, textContent: text };
}

function page(anchors) {
  return {
    URL: "https://watch.example/reference",
    baseURI: "https://watch.example/reference",
    defaultView: { confirm: () => true },
    querySelectorAll: (selector) => selector === "a[href]" ? anchors : [],
  };
}

function sessionResponse() {
  return Response.json({
    authenticated: true,
    csrf_token: "c".repeat(32),
    expires_at: "2026-09-01T07:00:00.000Z",
  });
}

function receiptResponse(overrides = {}) {
  return Response.json({
    mode: "live_page",
    analyzed_at: "2026-09-01T06:30:00.000Z",
    scan_ids: ["a".repeat(32)],
    observed_candidates: 1,
    accepted_targets: 1,
    rejected_candidates: 0,
    truncated: false,
    page_evidence_trust: "untrusted",
    targets: [{
      canonical_url: "https://watch.example/one",
      occurrence_indices: [0],
      anchor_text_variants: ["one"],
    }],
    rejections: [],
    ...overrides,
  }, { status: 201 });
}

test("live request parsing is exact, bounded, route-owned, and timestamp-bounded", () => {
  const observedAt = "2026-09-01T06:30:00.000Z";
  const now = Date.parse(observedAt);
  const value = {
    document_url: "https://watch.example/reference",
    observed_at: observedAt,
    candidates: [candidate("./one", "one", 0, observedAt)],
    extraction_rejections: [],
  };
  assert.deepEqual(parseLiveRequest(value, "https://watch.example", now), value);
  const fragmentDocument = "https://watch.example/reference#visible-section";
  const fragmentValue = {
    ...value,
    document_url: fragmentDocument,
    candidates: [candidate("./one", "one", 0, observedAt, {
      base_url: fragmentDocument,
      provenance: { ...value.candidates[0].provenance, document_url: fragmentDocument },
    })],
  };
  assert.deepEqual(parseLiveRequest(fragmentValue, "https://watch.example", now), fragmentValue);
  for (const invalid of [
    { ...value, extra: true },
    { ...value, document_url: "https://watch.example/elsewhere" },
    { ...value, document_url: "https://watch.example/reference.html" },
    { ...value, document_url: "https://watch.example/reference?probe=1" },
    { ...value, observed_at: "2026-09-01T06:20:00.000Z" },
    { ...value, candidates: [candidate("./one", "one", 1, observedAt)] },
    { ...value, candidates: [candidate("./one", "one", 0, observedAt, {
      base_url: "https://attacker.example/",
    })] },
    { ...value, candidates: Array(LIVE_LIMITS.max_candidates + 1).fill(value.candidates[0]) },
  ]) assert.equal(parseLiveRequest(invalid, "https://watch.example", now), null);
});

test("live candidates use shared canonicalization, deduplication, rejection, and analysis", async () => {
  const observedAt = "2026-09-01T06:30:00.000Z";
  const stored = [];
  const request = {
    document_url: "https://watch.example/reference",
    observed_at: observedAt,
    candidates: [
      candidate("./one#first", "First", 0, observedAt),
      candidate("https://watch.example/one#second", "Second", 1, observedAt),
      candidate("mailto:help@example.com", "Mail", 2, observedAt),
      candidate("https://accounts.invalid/login", "https://accounts.example/login", 3, observedAt),
    ],
    extraction_rejections: [],
  };
  const receipt = await executeLiveScan(request, {
    now: () => new Date(observedAt),
    store: async (result) => {
      stored.push(structuredClone(result));
      return String(stored.length).padStart(32, "0");
    },
  });
  assert.equal(receipt.page_evidence_trust, "untrusted");
  assert.equal(receipt.analyzed_at, observedAt);
  assert.equal(receipt.observed_candidates, 4);
  assert.equal(receipt.accepted_targets, 2);
  assert.equal(receipt.rejected_candidates, 1);
  assert.deepEqual(receipt.targets[0], {
    canonical_url: "https://watch.example/one",
    occurrence_indices: [0, 1],
    anchor_text_variants: ["First", "Second"],
  });
  assert.deepEqual(receipt.rejections, [{ occurrence_index: 2, reason: "unsupported_scheme" }]);
  assert.equal(stored[0].mode, "live_page");
  assert.equal(stored[0].canonical_target, "https://watch.example/one");
  assert.equal(stored[1].risk_label, "suspicious");
  assert.equal(stored[1].supporting_evidence[0].category, "misleading_url_like_text");
  assert.equal(stored[2].analysis_state, "unscannable");
});

test("raw and post-resolution URL limits retain typed live rejections", async () => {
  const observedAt = "2026-09-01T06:30:00.000Z";
  const rawHref = `./${"x".repeat(LIVE_LIMITS.max_href_chars - 2)}`;
  assert.equal(rawHref.length, LIVE_LIMITS.max_href_chars);
  const stored = [];
  const receipt = await executeLiveScan({
    document_url: "https://watch.example/reference",
    observed_at: observedAt,
    candidates: [candidate(rawHref, "long relative", 0, observedAt)],
    extraction_rejections: [],
  }, {
    now: () => new Date(observedAt),
    store: async (result) => { stored.push(result); return "a".repeat(32); },
  });
  assert.equal(new URL(rawHref, "https://watch.example/reference").href.length, 2_068);
  assert.deepEqual(receipt.targets, []);
  assert.deepEqual(receipt.rejections, [{ occurrence_index: 0, reason: "url_too_long" }]);
  assert.equal(receipt.accepted_targets, 0);
  assert.equal(stored[0].analysis_state, "unscannable");
  assert.match(stored[0].limitations[0], /url_too_long/);

  const extracted = extractRenderedPage(page([
    anchor("x".repeat(WEBMCP_LIMITS.maxHrefChars + 1), "oversized"),
    anchor("./retained", "retained"),
  ]), observedAt);
  assert.deepEqual(extracted.extraction_rejections, [
    { occurrence_index: 0, reason: "url_too_long" },
  ]);
  assert.equal(extracted.candidates[0].provenance.occurrence_index, 1);
});

test("the fixed Worker route requires session, origin, and CSRF then stores owned results", async () => {
  const env = configured();
  const secrets = readAuthSecrets(env);
  const session = await createSession(secrets);
  const cookie = session.cookie;
  const status = await worker.fetch(new Request("https://watch.example/api/session", {
    headers: { cookie },
  }), env);
  const statusBody = await status.json();
  assert.equal(statusBody.csrf_token, session.claims.csrf);

  const observedAt = new Date().toISOString();
  const body = JSON.stringify({
    document_url: "https://watch.example/reference",
    observed_at: observedAt,
    candidates: [candidate("./delayed-evidence", "delayed", 0, observedAt)],
    extraction_rejections: [],
  });
  const endpoint = "https://watch.example/api/scans/live";
  const denied = await worker.fetch(new Request(endpoint, {
    method: "POST", body, headers: { cookie, origin: "https://watch.example" },
  }), env);
  assert.equal(denied.status, 401);
  const accepted = await worker.fetch(new Request(endpoint, {
    method: "POST",
    body,
    headers: {
      cookie,
      origin: "https://watch.example",
      "x-watchdog-csrf": statusBody.csrf_token,
    },
  }), env);
  assert.equal(accepted.status, 201);
  const receipt = await accepted.json();
  assert.deepEqual(receipt.targets[0].canonical_url, "https://watch.example/delayed-evidence");
  const result = await worker.fetch(new Request(
    `https://watch.example/api/results/${receipt.scan_ids[0]}`,
    { headers: { cookie } },
  ), env);
  assert.equal((await result.json()).result.mode, "live_page");

  const overlong = `./${"x".repeat(LIVE_LIMITS.max_href_chars - 2)}`;
  const rejectedBody = JSON.stringify({
    document_url: "https://watch.example/reference",
    observed_at: observedAt,
    candidates: [candidate(overlong, "long", 0, observedAt)],
    extraction_rejections: [],
  });
  const rejected = await worker.fetch(new Request(endpoint, {
    method: "POST", body: rejectedBody,
    headers: { cookie, origin: "https://watch.example", "x-watchdog-csrf": statusBody.csrf_token },
  }), env);
  const rejectedReceipt = await rejected.json();
  assert.equal(rejected.status, 201);
  assert.deepEqual(rejectedReceipt.rejections, [{ occurrence_index: 0, reason: "url_too_long" }]);
  assert.equal(rejectedReceipt.accepted_targets, 0);
});

test("the fixed reference route lets Assets resolve extensionless paths and canonicalizes direct access", async () => {
  const seen = [];
  const env = { ASSETS: { fetch: async (request) => {
    seen.push(request.url);
    return new Response("reference asset");
  } } };
  assert.equal(await (await worker.fetch(new Request("https://watch.example/reference"), env)).text(),
    "reference asset");
  assert.deepEqual(seen, ["https://watch.example/reference"]);
  const direct = await worker.fetch(new Request("https://watch.example/reference.html?probe=1"), env);
  assert.equal(direct.status, 308);
  assert.equal(direct.headers.get("location"), "https://watch.example/reference");
  const queried = await worker.fetch(new Request("https://watch.example/reference?probe=1"), env);
  assert.equal(queried.status, 308);
  assert.equal(queried.headers.get("location"), "https://watch.example/reference");
  assert.deepEqual(seen, ["https://watch.example/reference"]);
});

test("each extraction observes the current rendered anchors instead of a source array", () => {
  const anchors = [
    anchor("https://example.com/one", "  First   link "),
    anchor("./relative", "Relative"),
  ];
  const pageDocument = page(anchors);
  const before = extractRenderedPage(pageDocument, "2026-09-01T06:30:00.000Z");
  anchors.push(anchor("./delayed-evidence", "Delayed"));
  const after = extractRenderedPage(pageDocument, "2026-09-01T06:30:01.000Z");
  assert.equal(before.candidates.length, 2);
  assert.equal(after.candidates.length, 3);
  assert.equal(after.candidates[2].raw_href, "./delayed-evidence");
  assert.equal(before.candidates[0].anchor_text, "First link");
  assert.ok(after.candidates.every((item, index) => item.provenance.occurrence_index === index));
  const many = Array.from({ length: WEBMCP_LIMITS.maxCandidates + 2 }, (_, i) =>
    anchor(`./${i}`, "x".repeat(WEBMCP_LIMITS.maxAnchorTextChars + 10)));
  const bounded = extractRenderedPage(page(many));
  assert.equal(bounded.candidates.length, WEBMCP_LIMITS.maxCandidates);
  assert.equal(bounded.candidates[0].anchor_text.length, WEBMCP_LIMITS.maxAnchorTextChars);
});

test("tool contract is literal, read-only, untrusted, cancellable, and invocation-time", async () => {
  const anchors = [anchor("./before", "Before")];
  const pageDocument = page(anchors);
  let confirmations = 0;
  pageDocument.defaultView.confirm = () => { confirmations += 1; return true; };
  const posts = [];
  const stored = new Map();
  const fetcher = async (url, init) => {
    if (url === "/api/session") return sessionResponse();
    if (url.startsWith("/api/results/")) {
      return Response.json({ status: "ok", result: stored.get(url.split("/").at(-1)) });
    }
    const body = JSON.parse(init.body);
    posts.push({ init, body });
    let serial = 0;
    return Response.json(await executeLiveScan(body, {
      now: () => new Date(body.observed_at),
      store: async (result) => {
        const id = (++serial).toString(16).padStart(32, "0");
        stored.set(id, { ...result, scan_id: id });
        return id;
      },
    }), { status: 201 });
  };
  const tool = createInspectCurrentPageTool(pageDocument, fetcher);
  assert.equal(tool.name, "inspect_current_page");
  assert.deepEqual(tool.inputSchema, {
    type: "object", properties: {}, additionalProperties: false,
  });
  assert.deepEqual(tool.annotations, { readOnlyHint: true, untrustedContentHint: true });
  assert.match(tool.description, /does not inspect unrelated tabs or navigate/);
  await tool.execute({});
  anchors.push(anchor("./after", "After"));
  await tool.execute({});
  assert.equal(confirmations, 2);
  assert.equal(posts[0].body.candidates.length, 1);
  assert.equal(posts[1].body.candidates.length, 2);
  assert.equal(posts[1].init.headers["x-watchdog-csrf"], "c".repeat(32));
  assert.ok(posts[1].init.signal instanceof AbortSignal);
  await assert.rejects(tool.execute({ target: "https://attacker.example" }), /invalid_arguments/);
  const aborted = new AbortController();
  aborted.abort();
  await assert.rejects(tool.execute({}, { signal: aborted.signal }), { name: "AbortError" });
});

test("in-flight cancellation reaches session, scan and result fetch phases", async () => {
  for (const blockedPhase of ["session", "scan", "result"]) {
    const controller = new AbortController();
    const calls = [];
    const fetcher = async (url, init) => {
      calls.push({ url, signal: init.signal });
      const phase = url === "/api/session" ? "session" :
        url === "/api/scans/live" ? "scan" : "result";
      if (phase !== blockedPhase) return phase === "session" ? sessionResponse() :
        phase === "scan" ? receiptResponse() : Response.json({ status: "ok", result: {} });
      return new Promise((_resolve, reject) => {
        init.signal.addEventListener("abort", () => reject(init.signal.reason), { once: true });
      });
    };
    const pending = inspectCurrentPage({ pageDocument: page([]), fetcher, signal: controller.signal });
    await new Promise((resolve) => setImmediate(resolve));
    controller.abort();
    await assert.rejects(pending, { name: "AbortError" });
    assert.match(calls.at(-1).url, blockedPhase === "session" ? /^\/api\/session$/u :
      blockedPhase === "scan" ? /^\/api\/scans\/live$/u : /^\/api\/results\//u);
    assert.ok(calls.every(({ signal }) => signal instanceof AbortSignal && signal.aborted));
  }
});

test("provider disclosure requires explicit per-invocation human consent", async () => {
  const pageDocument = page([]);
  pageDocument.defaultView.confirm = (message) => {
    assert.match(message, /canonical target URLs.*Google Safe Browsing/u);
    return false;
  };
  const calls = [];
  await assert.rejects(inspectCurrentPage({
    pageDocument, fetcher: async (url) => { calls.push(url); return sessionResponse(); },
  }), /provider_consent_required/u);
  assert.deepEqual(calls, ["/api/session"]);
});

test("malformed and transport failures use the closed browser error vocabulary", async () => {
  await assert.rejects(inspectCurrentPage({
    pageDocument: page([]),
    fetcher: async () => Response.json({ error: "unauthorized" }, { status: 401 }),
  }), /unauthorized/);
  await assert.rejects(inspectCurrentPage({
    pageDocument: page([]), fetcher: async () => { throw new TypeError("network down"); },
  }), /service_unavailable/);
  let resultCalls = 0;
  await assert.rejects(inspectCurrentPage({
    pageDocument: page([]), fetcher: async () => {
      resultCalls += 1;
      if (resultCalls === 1) return sessionResponse();
      if (resultCalls === 2) return receiptResponse();
      throw new TypeError("result network down");
    },
  }), /service_unavailable/);
  for (const malformedTransport of [null, 7, { ok: true }]) {
    for (const phase of ["session", "scan"]) {
      let calls = 0;
      await assert.rejects(inspectCurrentPage({
        pageDocument: page([]),
        fetcher: async () => ++calls === 1 && phase === "scan"
          ? sessionResponse()
          : malformedTransport,
      }), /service_unavailable/);
    }
  }
  for (const malformedScan of [
    new Response("not json", { status: 200 }),
    Response.json({ oops: true }),
    receiptResponse({ page_evidence_trust: "trusted" }),
    receiptResponse({ scan_ids: [["a".repeat(32)]] }),
    receiptResponse({ targets: [null] }),
    receiptResponse({ rejections: [null] }),
    receiptResponse({
      targets: [{
        canonical_url: "https://watch.example/one",
        occurrence_indices: [0],
        anchor_text_variants: Array(10_000).fill("one"),
      }],
    }),
    receiptResponse({
      targets: [{
        canonical_url: "https://watch.example/one",
        occurrence_indices: [],
        anchor_text_variants: ["one"],
      }],
    }),
  ]) {
    let calls = 0;
    await assert.rejects(inspectCurrentPage({
      pageDocument: page([]),
      fetcher: async () => ++calls === 1 ? sessionResponse() : malformedScan,
    }), /malformed_response/);
  }
  await assert.rejects(inspectCurrentPage({
    pageDocument: page([]), fetcher: async () => Response.json({ csrf_token: "short" }),
  }), /malformed_response/);
  await assert.rejects(inspectCurrentPage({
    pageDocument: page([]), fetcher: async () => Response.json({
      authenticated: true,
      csrf_token: ["c".repeat(32)],
      expires_at: "2026-09-01T07:00:00.000Z",
    }),
  }), /malformed_response/);
});

test("unsupported WebMCP status rendering is inert", async () => {
  const status = { value: "", set textContent(value) { this.value = value; },
    set innerHTML(_value) { assert.fail("status must remain inert"); } };
  const originalDocument = globalThis.document;
  try {
    globalThis.document = {
      modelContext: undefined,
      querySelector: (selector) => selector === "#webmcp-status" ? status : null,
    };
    assert.equal(await registerBrowserTool(), null);
    assert.match(status.value, /unavailable/);
  } finally {
    if (originalDocument === undefined) delete globalThis.document;
    else globalThis.document = originalDocument;
  }
});
