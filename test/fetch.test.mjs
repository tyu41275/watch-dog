import assert from "node:assert/strict";
import test from "node:test";
import { FETCH_REJECTION_REASONS } from "../dist/shared/canonicalize.js";

import { admitPublicHost, isPublicAddress } from "../dist/worker/fetch/address.js";
import { PASTE_LIMITS, executePasteScan, parsePasteRequest } from "../dist/worker/fetch/paste.js";
import { SAFE_FETCH_LIMITS, createCloudflareDohResolver, safeFetchHtml } from "../dist/worker/fetch/safe-fetch.js";

const PUBLIC_ADDRESSES = ["93.184.216.34", "2606:4700:4700::1111"];
const publicResolver = async () => PUBLIC_ADDRESSES;

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
    return Response.json({
      Status: 0,
      TC: false,
      Answer: v6
        ? [{ type: 5, data: "alias.example." }, { type: 28, data: PUBLIC_ADDRESSES[1] }]
        : [{ type: 1, data: PUBLIC_ADDRESSES[0] }],
    });
  });
  const addresses = await resolver("public.example.co", new AbortController().signal);
  assert.deepEqual(addresses, PUBLIC_ADDRESSES);
  assert.equal(calls.length, 2);
  assert.ok(calls.every(({ init }) => init.redirect === "error"));
  assert.ok(calls.every(({ init }) => init.headers.accept === "application/dns-json"));

  const invalid = createCloudflareDohResolver(async () => Response.json({ Status: 2 }));
  await assert.rejects(invalid("bad.example", new AbortController().signal), /dns response invalid/);

  const oversized = createCloudflareDohResolver(async () => Response.json({
    Status: 0, Answer: [], padding: "x".repeat(SAFE_FETCH_LIMITS.max_dns_response_bytes),
  }));
  await assert.rejects(oversized("large.example.co", new AbortController().signal), /body limit/);

  let cancelled = 0;
  const hanging = createCloudflareDohResolver(async () => new Response(new ReadableStream({
    pull() {}, cancel() { cancelled += 1; },
  })));
  const abort = new AbortController();
  setTimeout(() => abort.abort(), 5);
  await assert.rejects(hanging("slow.example.co", abort.signal));
  assert.equal(cancelled, 2);
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
    fetcher: async () => {
      calls += 1;
      return new Response(null, { status: 302, headers: { location: "http://127.0.0.1/metadata" } });
    },
  });
  assert.equal(privateRedirect.reason, "unsafe_address");
  assert.equal(calls, 1, "private redirect must not reach outbound fetch");

  const loop = await safeFetchHtml("https://public.example.co/a", {
    resolver: publicResolver,
    fetcher: async (url) => new Response(null, {
      status: 302,
      headers: { location: url.endsWith("/a") ? "/b" : "/a" },
    }),
  });
  assert.equal(loop.reason, "redirect_loop");

  const missing = await safeFetchHtml("https://public.example.co/", {
    resolver: publicResolver,
    fetcher: async () => new Response(null, { status: 302 }),
  });
  assert.equal(missing.reason, "redirect_missing_location");

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
    resolver: async () => { throw new TypeError("dns unavailable"); }, fetcher: async () => {
      throw new Error("must not fetch");
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

  const stored = [];
  let fetched = false;
  const receipt = await executePasteScan({
    mode: "html",
    base_url: "https://source.example/dir/page",
    html: '<script>throw 1</script><img src="https://never.invalid/x"><a href="../one">one</a><a href="mailto:x@y">mail</a>',
  }, {
    now: () => new Date("2026-09-01T03:00:00Z"),
    fetch_seams: { fetcher: async () => { fetched = true; throw new Error("unexpected"); } },
    store: async (result) => { stored.push(structuredClone(result)); return String(stored.length).padStart(32, "0"); },
  });
  assert.equal(fetched, false);
  assert.equal(receipt.mode, "paste_html");
  assert.equal(receipt.accepted_targets, 1);
  assert.equal(receipt.rejected_candidates, 1);
  assert.equal(stored[0].canonical_target, "https://source.example/one");
  assert.equal(stored[0].analysis_state, "unknown");
  assert.equal(stored[1].analysis_state, "unscannable");
  assert.match(stored[1].limitations[0], /unsupported_scheme/);
});

test("URL paste provenance is paste_url and failures produce stored typed fallback", async () => {
  const stored = [];
  const store = async (result) => { stored.push(structuredClone(result)); return "a".repeat(32); };
  const success = await executePasteScan({ mode: "url", url: "https://public.example.co/page" }, {
    now: () => new Date("2026-09-01T03:00:00Z"),
    store,
    fetch_seams: {
      resolver: publicResolver,
      fetcher: async () => new Response(
        '<a href="https://target.example/login">https://other.example/login</a>',
        { headers: { "content-type": "text/html" } },
      ),
    },
  });
  assert.equal(success.accepted_targets, 1);
  assert.equal(stored[0].mode, "paste_url");
  assert.equal(stored[0].supporting_evidence[0].source, "candidate:paste_url");

  stored.length = 0;
  const denied = await executePasteScan({ mode: "url", url: "http://127.0.0.1/" }, { store });
  assert.equal(denied.unscannable_reason, "unsafe_address");
  assert.equal(stored[0].analysis_state, "unscannable");
  assert.equal(denied.fetch_evidence.requested_url, "http://127.0.0.1/");

  const oversized = await executePasteScan({
    mode: "html", base_url: "https://source.example/", html: "x".repeat(200_001),
  }, { store });
  assert.equal(oversized.unscannable_reason, "input_too_large");

  for (const input of [
    { mode: "html", base_url: `https://source.example/${"b".repeat(2_040)}/`, html: '<a href="relative">x</a>' },
    { mode: "html", base_url: "https://source.example/", html: `<a href="${"r".repeat(2_048)}">x</a>` },
  ]) {
    stored.length = 0;
    const bounded = await executePasteScan(input, { store });
    assert.equal(bounded.unscannable_reason, "url_too_long");
    assert.equal(bounded.accepted_targets, 0);
    assert.equal(stored[0].analysis_state, "unscannable");
  }
  assert.equal(PASTE_LIMITS.max_results, 16);
});
