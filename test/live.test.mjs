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
  extractRenderedCandidates,
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
    querySelectorAll: (selector) => selector === "a[href]" ? anchors : [],
  };
}

test("live request parsing is exact, bounded, route-owned, and timestamp-bounded", () => {
  const observedAt = "2026-09-01T06:30:00.000Z";
  const now = Date.parse(observedAt);
  const value = {
    document_url: "https://watch.example/reference",
    observed_at: observedAt,
    candidates: [candidate("./one", "one", 0, observedAt)],
  };
  assert.deepEqual(parseLiveRequest(value, "https://watch.example", now), value);
  for (const invalid of [
    { ...value, extra: true },
    { ...value, document_url: "https://watch.example/elsewhere" },
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
  };
  const receipt = await executeLiveScan(request, {
    now: () => new Date(observedAt),
    store: async (result) => {
      stored.push(structuredClone(result));
      return String(stored.length).padStart(32, "0");
    },
  });
  assert.equal(receipt.page_evidence_trust, "untrusted");
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
});

test("the fixed reference route rewrites only the asset request", async () => {
  const seen = [];
  const env = { ASSETS: { fetch: async (request) => {
    seen.push(request.url);
    return new Response("reference asset");
  } } };
  assert.equal(await (await worker.fetch(new Request("https://watch.example/reference"), env)).text(),
    "reference asset");
  assert.deepEqual(seen, ["https://watch.example/reference.html"]);
});

test("each extraction observes the current rendered anchors instead of a source array", () => {
  const anchors = [
    anchor("https://example.com/one", "  First   link "),
    anchor("./relative", "Relative"),
  ];
  const pageDocument = page(anchors);
  const before = extractRenderedCandidates(pageDocument, "2026-09-01T06:30:00.000Z");
  anchors.push(anchor("./delayed-evidence", "Delayed"));
  const after = extractRenderedCandidates(pageDocument, "2026-09-01T06:30:01.000Z");
  assert.equal(before.length, 2);
  assert.equal(after.length, 3);
  assert.equal(after[2].raw_href, "./delayed-evidence");
  assert.equal(before[0].anchor_text, "First link");
  assert.ok(after.every((item, index) => item.provenance.occurrence_index === index));
  const many = Array.from({ length: WEBMCP_LIMITS.maxCandidates + 2 }, (_, i) =>
    anchor(`./${i}`, "x".repeat(WEBMCP_LIMITS.maxAnchorTextChars + 10)));
  const bounded = extractRenderedCandidates(page(many));
  assert.equal(bounded.length, WEBMCP_LIMITS.maxCandidates);
  assert.equal(bounded[0].anchor_text.length, WEBMCP_LIMITS.maxAnchorTextChars);
});

test("tool contract is literal, read-only, untrusted, cancellable, and invocation-time", async () => {
  const anchors = [anchor("./before", "Before")];
  const pageDocument = page(anchors);
  const posts = [];
  const fetcher = async (url, init) => {
    if (url === "/api/session") return Response.json({ csrf_token: "csrf" });
    posts.push({ init, body: JSON.parse(init.body) });
    return Response.json({
      mode: "live_page", scan_ids: ["a".repeat(32)], observed_candidates: init.body.length,
      accepted_targets: 1, rejected_candidates: 0, truncated: false,
      page_evidence_trust: "untrusted", targets: [], rejections: [],
    }, { status: 201 });
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
  assert.equal(posts[0].body.candidates.length, 1);
  assert.equal(posts[1].body.candidates.length, 2);
  assert.equal(posts[1].init.headers["x-watchdog-csrf"], "csrf");
  assert.equal(posts[1].init.signal, undefined);
  await assert.rejects(tool.execute({ target: "https://attacker.example" }), /invalid_arguments/);
  const aborted = new AbortController();
  aborted.abort();
  await assert.rejects(tool.execute({}, { signal: aborted.signal }), { name: "AbortError" });
});

test("fetch and registration failures stay typed and status rendering is inert", async () => {
  await assert.rejects(inspectCurrentPage({
    pageDocument: page([]),
    fetcher: async () => Response.json({ error: "unauthorized" }, { status: 401 }),
  }), /unauthorized/);
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
