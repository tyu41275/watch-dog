import assert from "node:assert/strict";
import test from "node:test";
import { FETCH_REJECTION_REASONS } from "../dist/shared/canonicalize.js";
import { admitPublicHost, isPublicAddress } from "../dist/worker/fetch/address.js";
import { PASTE_LIMITS, executePasteScan, parsePasteRequest } from "../dist/worker/fetch/paste.js";
import { SAFE_FETCH_LIMITS, createCloudflareDohResolver, safeFetchHtml } from "../dist/worker/fetch/safe-fetch.js";
import { replayFetchMachine } from "../dist/worker/fetch/fetch-machine.js";
import { createResponseScope } from "../dist/worker/fetch/response-scope.js";
import { CoordinatorCore } from "../dist/worker/coordinator.js";
import { extractHtmlScanAtoms } from "../dist/shared/extract-html.js";
const PUBLIC_ADDRESSES = ["93.184.216.34", "2606:4700:4700::1111"];
const publicResolver = async () => PUBLIC_ADDRESSES;
const dnsJson = (body, headers = { "content-type": "application/dns-json" }) => new Response(JSON.stringify(body), { headers });
const commit = (operation) => {
  const core = new CoordinatorCore();
  const receipt = core.commitPaste("s".repeat(32), operation.input, operation.journal, 0);
  return { receipt, results: receipt.scan_ids.map((id) => core.getResult("s".repeat(32), id, 0).result) };
};
test("address admission rejects every special family and mixed DNS before fetch", async () => {
  const cases = [
    ["8.8.8.8", true], ["93.184.216.34", true], ["0.0.0.0", false],
    ["10.0.0.1", false], ["100.64.0.1", false], ["127.0.0.1", false],
    ["169.254.169.254", false], ["172.31.0.1", false], ["192.168.1.1", false],
    ["192.0.2.1", false], ["198.18.0.1", false], ["198.51.100.1", false],
    ["192.31.196.1", false], ["192.52.193.1", false], ["192.175.48.1", false],
    ["203.0.113.1", false], ["224.0.0.1", false], ["255.255.255.255", false],
    ["2606:4700:4700::1111", true], ["::", false], ["::1", false],
    ["::ffff:127.0.0.1", false], ["64:ff9b::808:808", false],
    ["2001:db8::1", false], ["2002:0808:0808::", false], ["fc00::1", false],
    ["2620:4f:8000::1", false], ["3fff::1", false], ["5f00::1", false],
    ["fe80::1", false], ["ff02::1", false],
  ];
  for (const [address, expected] of cases) assert.equal(isPublicAddress(address), expected, address);
  let resolutions = 0;
  const controller = new AbortController();
  assert.deepEqual(await admitPublicHost("127.0.0.1", async () => {
    resolutions += 1;
    return PUBLIC_ADDRESSES;
  }, controller.signal), { ok: false, reason: "unsafe_address" });
  assert.equal(resolutions, 0);
  assert.deepEqual(await admitPublicHost(
    "mixed.example.co", async () => ["93.184.216.34", "10.0.0.1"], controller.signal,
  ), { ok: false, reason: "mixed_address" });
  assert.equal((await admitPublicHost("public.example.co", publicResolver, controller.signal)).ok, true);
  for (const hostname of ["localhost", "localhost.", "foo.localhost.", "example.com.", "service.arpa."]) {
    assert.deepEqual(await admitPublicHost(hostname, async () => {
      resolutions += 1; return PUBLIC_ADDRESSES;
    }, controller.signal), { ok: false, reason: "unsafe_address" }, hostname);
  }
  assert.equal(resolutions, 0);
  assert.deepEqual(await admitPublicHost("reserved.example", publicResolver, controller.signal),
    { ok: false, reason: "unsafe_address" });
  assert.deepEqual(await admitPublicHost("missing.example.co", async () => [], controller.signal),
    { ok: false, reason: "dns_failure" });
});
test("fetch rejection reasons are a closed literal vocabulary", () => {
  assert.deepEqual(FETCH_REJECTION_REASONS, [
    "url_too_long", "unsafe_address", "dns_failure", "mixed_address",
    "redirect_missing_location", "redirect_loop", "redirect_limit", "timeout",
    "response_too_large", "unsupported_content_type", "unsupported_content_encoding",
    "fetch_failed", "invalid_response", "input_too_large", "no_candidates",
  ]);
});
test("Cloudflare DoH resolver bounds and extracts only A and AAAA answers", async () => {
  const calls = [];
  const resolver = createCloudflareDohResolver(async (url, init) => {
    calls.push({ url, init });
    const v6 = url.includes("type=AAAA");
    return dnsJson({ Status: 0, TC: false, Answer: v6
        ? [{ type: 5, data: "alias.example." }, { type: 28, data: PUBLIC_ADDRESSES[1] }]
        : [{ type: 1, data: PUBLIC_ADDRESSES[0] }],
    });
  });
  const addresses = await resolver("public.example.co", new AbortController().signal);
  assert.deepEqual(addresses, PUBLIC_ADDRESSES);
  assert.equal(calls.length, 2);
  assert.ok(calls.every(({ init }) => init.redirect === "error" && init.headers.accept === "application/dns-json"));
  for (const [body, headers] of [
    [{ Status: 2 }], [{ Status: 0, Answer: [{ type: 1, data: PUBLIC_ADDRESSES[0] }] }], [{ Status: 0, TC: "true", Answer: [] }],
    [{ Status: 0, TC: 1, Answer: [] }], [{ Status: 0, TC: false, Answer: [{ type: "1", data: PUBLIC_ADDRESSES[0] }] }], [{ Status: 0, TC: false, Answer: [{ type: 1, data: null }] }], [{ Status: 0, TC: false, Answer: [{ type: 1, data: "not-an-ip" }] }], [{ Status: 0, TC: false, Answer: [{ type: 1, data: PUBLIC_ADDRESSES[1] }] }], [{ Status: 0, TC: false, Answer: [{ type: 28, data: PUBLIC_ADDRESSES[0] }] }], [{ Status: 0, TC: false, Answer: [] }, { "content-type": "text/html" }], [{ Status: 0, TC: false, Answer: [] }, { "content-type": "application/dns-json", "content-encoding": "gzip" }],
  ]) {
    await assert.rejects(createCloudflareDohResolver(async () => dnsJson(body, headers))("bad.example", new AbortController().signal), /dns response/);
  }
  const oversized = createCloudflareDohResolver(async () => dnsJson({
    Status: 0, TC: false, Answer: [], padding: "x".repeat(SAFE_FETCH_LIMITS.max_dns_response_bytes),
  }));
  await assert.rejects(oversized("large.example.co", new AbortController().signal), /body limit/);
  let cancelled = 0;
  const hanging = createCloudflareDohResolver(async () => new Response(new ReadableStream({
    pull() {}, cancel() { cancelled += 1; },
  }), { headers: { "content-type": "application/dns-json" } }));
  const abort = new AbortController();
  setTimeout(() => abort.abort(), 5);
  await assert.rejects(hanging("slow.example.co", abort.signal));
  assert.equal(cancelled, 2);
  cancelled = 0;
  const failedSibling = createCloudflareDohResolver(async (url) => url.endsWith("type=A")
    ? dnsJson({ Status: 2 })
    : new Response(new ReadableStream({ pull() {}, cancel() { cancelled += 1; } }), { headers: { "content-type": "application/dns-json" } }));
  await assert.rejects(failedSibling("sibling.example.co", new AbortController().signal));
  assert.equal(cancelled, 1);
});
test("safe fetch revalidates relative redirects and returns bounded HTML evidence", async () => {
  const fetchCalls = [];
  const resolveCalls = [];
  const result = await safeFetchHtml("HTTPS://Public.Example.co/start#fragment", {
    resolver: async (hostname) => { resolveCalls.push(hostname); return PUBLIC_ADDRESSES; },
    fetcher: async (url, init) => {
      fetchCalls.push({ url, init });
      return url.endsWith("/start")
        ? new Response(null, { status: 302, headers: { location: "/final" } })
        : new Response('<a href="/next">next</a>', { headers: { "content-type": "text/html; charset=utf-8" } });
    },
  });
  assert.equal(result.ok && result.html, '<a href="/next">next</a>');
  assert.deepEqual(result.evidence.redirect_chain, ["https://public.example.co/final"]);
  assert.deepEqual(resolveCalls, ["public.example.co", "public.example.co"]);
  assert.equal(fetchCalls.length, 2);
  assert.ok(fetchCalls.every(({ init }) => init.redirect === "manual"));
  assert.ok(fetchCalls.every(({ init }) => init.headers["accept-encoding"] === "identity"));
  assert.deepEqual(result.evidence.validated_hops.map((hop) => hop.address_count), [2, 2]);
});
test("redirect private targets, loops, missing locations, and limits fail closed", async () => {
  let calls = 0;
  const privateRedirect = await safeFetchHtml("https://public.example.co/start", {
    resolver: publicResolver,
    fetcher: async () => new Response(null, {
      status: 302, headers: { location: (calls += 1, "http://127.0.0.1/metadata") },
    }),
  });
  assert.equal(privateRedirect.reason, "unsafe_address");
  assert.equal(calls, 1, "private redirect must not reach outbound fetch");
  const loop = await safeFetchHtml("https://public.example.co/a", {
    resolver: publicResolver,
    fetcher: async (url) => new Response(null, {
      status: 302, headers: { location: url.endsWith("/a") ? "/b" : "/a" },
    }),
  });
  assert.equal(loop.reason, "redirect_loop");
  const missing = await safeFetchHtml("https://public.example.co/", {
    resolver: publicResolver, fetcher: async () => new Response(null, { status: 302 }),
  });
  assert.equal(missing.reason, "redirect_missing_location");
  const longLocation = await safeFetchHtml("https://public.example.co/", { resolver: publicResolver, fetcher: async () => new Response(null, { status: 302, headers: { location: `/${"x/../".repeat(500)}final` } }) });
  assert.equal(longLocation.reason, "url_too_long");
  const limited = await safeFetchHtml("https://public.example.co/r0", {
    resolver: publicResolver,
    fetcher: async (url) => {
      const next = Number(new URL(url).pathname.slice(2)) + 1;
      return new Response(null, { status: 302, headers: { location: `/r${next}` } });
    },
  });
  assert.equal(limited.reason, "redirect_limit");
  assert.equal(limited.evidence.redirect_chain.length, SAFE_FETCH_LIMITS.max_redirects);
});
test("response, encoding, byte, fetch, DNS, and time limits are typed", async () => {
  const cases = [
    ["content", () => new Response("{}", { headers: { "content-type": "application/json" } }), "unsupported_content_type"],
    ["encoding", () => new Response("x", { headers: { "content-type": "text/html", "content-encoding": "gzip" } }), "unsupported_content_encoding"],
    ["length", () => new Response("x", { headers: {
      "content-type": "text/html", "content-length": String(SAFE_FETCH_LIMITS.max_response_bytes + 1),
    } }), "response_too_large"],
    ["length mismatch", () => new Response("x", { headers: { "content-type": "text/html", "content-length": "2" } }), "invalid_response"],
    ["bytes", () => new Response(new Uint8Array(SAFE_FETCH_LIMITS.max_response_bytes + 1), {
      headers: { "content-type": "text/html" },
    }), "response_too_large"],
    ["status", () => new Response("no", { status: 503 }), "invalid_response"],
  ];
  for (const [name, response, reason] of cases) {
    const result = await safeFetchHtml("https://public.example.co/", {
      resolver: publicResolver, fetcher: async () => response(),
    });
    assert.equal(result.reason, reason, name);
  }
  const failed = await safeFetchHtml("https://public.example.co/", {
    resolver: publicResolver, fetcher: async () => { throw new TypeError("network unavailable"); },
  });
  assert.equal(failed.reason, "fetch_failed");
  const dns = await safeFetchHtml("https://missing.example.co/", {
    resolver: createCloudflareDohResolver(async (url) => dnsJson({ Status: 0, TC: false, Answer: url.endsWith("type=A") ? [{ type: 1, data: PUBLIC_ADDRESSES[1] }] : [{ type: 28, data: PUBLIC_ADDRESSES[1] }] })), fetcher: async () => {
      assert.fail("wrong-family DNS must not fetch");
    },
  });
  assert.equal(dns.reason, "dns_failure");
  const timeout = await safeFetchHtml("https://public.example.co/", {
    resolver: publicResolver,
    operation_ms: 5,
    fetcher: async (_url, { signal }) => new Promise((_resolve, reject) => {
      signal.addEventListener("abort", () => reject(new DOMException("aborted", "AbortError")));
    }),
  });
  assert.equal(timeout.reason, "timeout");
  const invalidUtf8 = await safeFetchHtml("https://public.example.co/", {
    resolver: publicResolver, fetcher: async () => new Response(new Uint8Array([0xc3, 0x28]), {
      headers: { "content-type": "text/html" },
    }),
  });
  assert.equal(invalidUtf8.reason, "invalid_response");
  let cancelledOversize = false;
  const declaredOversize = await safeFetchHtml("https://public.example.co/", {
    resolver: publicResolver,
    fetcher: async () => new Response(new ReadableStream({
      pull() {}, cancel() { cancelledOversize = true; },
    }), { headers: {
      "content-type": "text/html",
      "content-length": String(SAFE_FETCH_LIMITS.max_response_bytes + 1),
    } }),
  });
  assert.deepEqual([declaredOversize.reason, cancelledOversize], ["response_too_large", true]);
  const hangingBody = new ReadableStream({ pull() {} });
  const bodyTimeout = await safeFetchHtml("https://public.example.co/", {
    resolver: publicResolver,
    operation_ms: 5,
    fetcher: async () => new Response(hangingBody, { headers: { "content-type": "text/html" } }),
  });
  assert.equal(bodyTimeout.reason, "timeout");
  let expiredCancelled = false;
  let clockStep = 0;
  const expiredBeforeBody = await safeFetchHtml("https://public.example.co/", {
    resolver: publicResolver, total_ms: 8, now: () => [0, 0, 0, 9][clockStep++] ?? 9,
    fetcher: async () => new Response(new ReadableStream({
      pull() {}, cancel() { expiredCancelled = true; },
    }), { headers: { "content-type": "text/html" } }),
  });
  assert.deepEqual([expiredBeforeBody.reason, expiredCancelled], ["timeout", true]);
  const tooLong = await safeFetchHtml(`https://public.example.co/${"x".repeat(2_100)}`);
  assert.equal(tooLong.reason, "url_too_long");
  assert.equal(tooLong.evidence.requested_url, "");
});
test("paste input is closed and local HTML stays inert on the shared pipeline", async () => {
  assert.deepEqual(parsePasteRequest({ mode: "url", url: "https://public.example.co/" }), {
    mode: "url", url: "https://public.example.co/",
  });
  assert.equal(parsePasteRequest({ mode: "url", url: "https://public.example.co/", extra: true }), null);
  assert.equal(parsePasteRequest({ mode: "html", html: "x" }), null);
  let fetched = false;
  const operation = await executePasteScan({
    mode: "html",
    base_url: "https://source.example/dir/page",
    html: '<script>throw 1</script><img src="https://never.invalid/x"><a href="../one">one</a><a href="mailto:x@y">mail</a>',
  }, {
    now: () => new Date("2026-09-01T03:00:00Z"),
    fetch_seams: { fetcher: async () => { fetched = true; throw new Error("unexpected"); } },
  });
  const { receipt, results: stored } = commit(operation);
  assert.equal(fetched, false);
  assert.deepEqual(Object.keys(operation).sort(), ["input", "journal", "version"]);
  assert.ok(operation.journal.every(({ effect }) => effect.kind !== "ALLOCATE_IDS"));
  assert.ok(Object.isFrozen(operation.input) && Object.isFrozen(operation.journal));
  assert.equal(receipt.mode, "paste_html");
  assert.equal(receipt.accepted_targets, 1);
  assert.equal(receipt.rejected_candidates, 1);
  assert.equal(stored[0].canonical_target, "https://source.example/one");
  assert.equal(stored[0].analysis_state, "provider_error");
  assert.equal(stored[1].analysis_state, "unscannable");
  assert.match(stored[1].limitations[0], /unsupported_scheme/);
});
test("URL paste provenance is paste_url and failures produce stored typed fallback", async () => {
  const successOperation = await executePasteScan({ mode: "url", url: "https://public.example.co/page" }, {
    now: () => new Date("2026-09-01T03:00:00Z"),
    fetch_seams: {
      resolver: publicResolver,
      fetcher: async () => new Response(
        '<a href="https://target.example/login">https://other.example/login</a>',
        { headers: { "content-type": "text/html" } },
      ),
    },
  });
  const { receipt: success, results: stored } = commit(successOperation);
  assert.equal(success.accepted_targets, 1);
  assert.equal(stored[0].mode, "paste_url");
  assert.equal(stored[0].supporting_evidence[0].source, "candidate:paste_url");
  const deniedOperation = await executePasteScan({ mode: "url", url: "http://127.0.0.1/" });
  const { receipt: denied, results: deniedResults } = commit(deniedOperation);
  assert.equal(denied.unscannable_reason, "unsafe_address");
  assert.equal(deniedResults[0].analysis_state, "unscannable");
  assert.equal(denied.fetch_evidence.requested_url, "http://127.0.0.1/");
  const oversizedOperation = await executePasteScan({
    mode: "html", base_url: "https://source.example/", html: "x".repeat(200_001),
  });
  const { receipt: oversized } = commit(oversizedOperation);
  assert.equal(oversized.unscannable_reason, "input_too_large");
  for (const input of [
    { mode: "html", base_url: `https://source.example/${"b".repeat(2_040)}/`, html: '<a href="relative">x</a>' },
    { mode: "html", base_url: "https://source.example/", html: `<a href="${"r".repeat(2_048)}">x</a>` },
  ]) {
    const boundedOperation = await executePasteScan(input);
    const { receipt: bounded, results } = commit(boundedOperation);
    assert.equal(bounded.unscannable_reason, "url_too_long");
    assert.equal(bounded.accepted_targets, 0);
    assert.equal(results[0].analysis_state, "unscannable");
  }
  assert.equal(PASTE_LIMITS.max_results, 16);
});

test("actual Paste extraction emits exact overflow primitives without late bytes", () => {
  const anchors = (count) => Array.from({ length: count }, (_, index) =>
    `<a href="/item-${index}">${index}</a>`).join("");
  assert.equal(extractHtmlScanAtoms(anchors(255)).length, 255);
  assert.equal(extractHtmlScanAtoms(anchors(256)).length, 256);
  const overflow = extractHtmlScanAtoms(`${anchors(256)}<a href="/late-value">late</a>`);
  assert.deepEqual(overflow.at(-1), { kind: "OCCURRENCE_OVERFLOW" });
  assert.equal(JSON.stringify(overflow).includes("late-value"), false);
  const [href, exact, text, trailing, separated, missing] = extractHtmlScanAtoms(`<a href="${"h".repeat(2049)}">x</a><a href="/exact">${"x".repeat(512)}   </a><a href="/text">${"x".repeat(512)} y</a><a href="/trailing">${"x".repeat(511)}   </a><a href="/separated">${"x".repeat(511)}   y</a><a>missing</a>`);
  assert.deepEqual([href.href, href.href_overflow], [null, true]);
  assert.deepEqual([exact.text.length, exact.text_overflow], [512, false]);
  assert.deepEqual([text.text.length, text.text_overflow], [512, true]); assert.deepEqual([trailing.text, trailing.text_overflow], ["x".repeat(511), false]);
  assert.equal(missing, undefined); assert.deepEqual([separated.text, separated.text_overflow], [`${"x".repeat(511)} `, true]);
});
test("Paste cancellation cannot produce a coordinator-ready prefix", async () => {
  const before = new AbortController(); before.abort();
  await assert.rejects(executePasteScan({ mode: "html", base_url: "https://source.example/",
    html: '<a href="/one">one</a>' }, { signal: before.signal }), /abort/i);
  const during = new AbortController();
  const provider = { provider: "google_safe_browsing", source: "live", observe: async (request) => {
    during.abort(); return { provider: "google_safe_browsing", source: "live",
      queried_target: request.canonical_target, observed_at: request.requested_at, expires_at: null,
      freshness: "unknown", state: "no_match", category: null, confidence: "low", reference: null, error: null };
  } };
  await assert.rejects(executePasteScan({ mode: "html", base_url: "https://source.example/",
    html: '<a href="/one">one</a>' }, { signal: during.signal, provider }), /abort/i);
});

const deferred = () => {
  let resolve; let reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
};
const cancellable = (cancel) => new Response(new ReadableStream({ pull() {}, cancel }), {
  headers: { "content-type": "text/html" },
});

test("response scope seals pending tickets, bounds cells, and rejects forged or reused handles", async () => {
  const pending = [deferred(), deferred()]; let calls = 0; let cancelled = 0;
  const scope = createResponseScope(() => pending[calls++].promise, () => 0);
  const first = scope.request("https://one.example.co/", {}, 10);
  const second = scope.request("https://two.example.co/", {}, 10);
  assert.equal((await scope.request("https://three.example.co/", {}, 10)).failure, "capacity");
  const receipt = scope.seal();
  assert.deepEqual([receipt.live_handles, receipt.pending_tickets], [0, 2]);
  assert.equal((await first).failure, "timeout"); assert.equal((await second).failure, "timeout");
  pending[0].resolve(cancellable(() => { cancelled += 1; return Promise.reject(new Error("observed")); }));
  pending[1].resolve(cancellable(() => { cancelled += 1; return new Promise(() => {}); }));
  await new Promise(setImmediate);
  assert.equal(cancelled, 2);

  const owned = createResponseScope(async () => new Response("ok", { headers: { "content-type": "text/html" } }), () => 0);
  const acquired = await owned.request("https://owned.example.co/", {}, 10);
  assert.equal(acquired.ok, true);
  assert.equal(owned.metadata({}, {}).ok, false);
  const metadata = owned.metadata(acquired.handle, { "content-type": 32 });
  assert.equal(metadata.ok, true);
  assert.equal(owned.metadata(acquired.handle, {}).ok, false);
  assert.equal(owned.discard(metadata.handle), true);
  assert.equal(owned.discard(metadata.handle), false);
  assert.equal(owned.seal().live_handles, 0);
  const thrown = createResponseScope(() => { throw new Error("synchronous fetch failure"); }, () => 0);
  assert.equal((await thrown.request("https://throw.example.co/", {}, 10)).failure, "network_error"); thrown.seal();
});

test("scope completion clocks and seal order cancel once with zero unhandled rejection", async () => {
  const unhandled = []; const onUnhandled = (reason) => unhandled.push(reason);
  process.on("unhandledRejection", onUnhandled);
  try {
    for (const mode of ["throw", "reject", "never"]) {
      let cancelled = 0;
      const scope = createResponseScope(async () => cancellable(() => {
        cancelled += 1;
        if (mode === "throw") throw new Error("cancel throw");
        return mode === "reject" ? Promise.reject(new Error("cancel reject")) : new Promise(() => {});
      }), () => 0);
      const acquired = await scope.request("https://read.example.co/", {}, 10);
      const reading = scope.read(acquired.handle, 10, 10);
      scope.seal();
      assert.equal((await reading).failure, "timeout");
      const direct = createResponseScope(async () => cancellable(() => {
        cancelled += 1; if (mode === "throw") throw new Error("discard throw");
        return mode === "reject" ? Promise.reject(new Error("discard reject")) : new Promise(() => {});
      }), () => 0);
      const directHandle = await direct.request("https://discard.example.co/", {}, 10);
      assert.equal(direct.discard(directHandle.handle), true);
      const directReceipt = direct.seal(); if (mode === "never") assert.equal(directReceipt.cancel_pending, 1);
      assert.equal(cancelled, 2);
    }
    let boundaryClock = 0; let boundaryCancelled = 0; const boundary = deferred();
    const exact = createResponseScope(() => boundary.promise, () => boundaryClock);
    const exactRequest = exact.request("https://boundary.example.co/", {}, 10);
    boundaryClock = 10; boundary.resolve(cancellable(() => { boundaryCancelled += 1; }));
    assert.equal((await exactRequest).ok, true); exact.seal();
    assert.equal(boundaryCancelled, 1);
    let clock = 0; let lateCancelled = 0; const late = deferred();
    const timed = createResponseScope(() => late.promise, () => clock);
    const acquiring = timed.request("https://late.example.co/", {}, 10);
    clock = 11; late.resolve(cancellable(() => { lateCancelled += 1; }));
    assert.equal((await acquiring).failure, "timeout");
    assert.equal(lateCancelled, 1);
    assert.equal(timed.seal().live_handles, 0);
    await new Promise(setImmediate);
    assert.deepEqual(unhandled, []);
  } finally { process.off("unhandledRejection", onUnhandled); }
});

test("late DoH siblings and destination fulfillment remain owned after logical settlement", async () => {
  let cancelled = 0;
  const doh = [deferred(), deferred()]; let dohCall = 0;
  const dohResult = await safeFetchHtml("https://public.example.co/", {
    operation_ms: 5, fetcher: () => doh[dohCall++].promise,
  });
  assert.equal(dohResult.reason, "timeout");
  doh[0].resolve(cancellable(() => { cancelled += 1; })); doh[1].resolve(cancellable(() => { cancelled += 1; }));
  await new Promise(setImmediate);
  assert.equal(cancelled, 2);

  const sibling = deferred(); let siblingCalls = 0;
  const siblingResult = await safeFetchHtml("https://public.example.co/", {
    fetcher: (url) => siblingCalls++ === 0
      ? Promise.resolve(dnsJson({ Status: 2, TC: false })) : sibling.promise,
  });
  assert.equal(siblingResult.reason, "dns_failure");
  sibling.resolve(cancellable(() => { cancelled += 1; }));
  await new Promise(setImmediate);
  assert.equal(cancelled, 3);

  const destination = deferred();
  const destinationResult = await safeFetchHtml("https://public.example.co/", {
    resolver: publicResolver, operation_ms: 5, fetcher: () => destination.promise,
  });
  assert.equal(destinationResult.reason, "timeout");
  destination.resolve(cancellable(() => { cancelled += 1; }));
  await new Promise(setImmediate);
  assert.equal(cancelled, 4);
});

test("production journal is immutable, sanitized, replayable, and all-dot admission is effect-free", async () => {
  let effects = 0;
  const refused = await safeFetchHtml("https://./", {
    resolver: async () => { effects += 1; return PUBLIC_ADDRESSES; },
    fetcher: async () => { effects += 1; throw new Error("unreachable"); },
  });
  assert.equal(refused.ok, false); assert.equal(effects, 0);
  const entries = [];
  const result = await safeFetchHtml("https://public.example.co/", {
    now: () => 0, resolver: publicResolver,
    fetcher: async () => new Response("safe", { headers: { "content-type": "text/html" } }),
    record: (entry) => { entries.push(entry); assert.throws(() => { entry.fact.kind = "forged"; }, TypeError); },
  });
  assert.equal(result.ok, true);
  const replayed = replayFetchMachine("https://public.example.co/", {
    max_url_chars: SAFE_FETCH_LIMITS.max_url_chars, max_redirects: SAFE_FETCH_LIMITS.max_redirects,
    max_response_bytes: SAFE_FETCH_LIMITS.max_response_bytes, operation_ms: SAFE_FETCH_LIMITS.per_operation_ms,
    total_ms: SAFE_FETCH_LIMITS.total_ms,
  }, 0, entries);
  assert.equal(replayed.ok, true);
  assert.equal(/response_handle|"html":|"bytes":|"body":/.test(JSON.stringify(entries)), false);
});
