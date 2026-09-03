import assert from "node:assert/strict";
import test from "node:test";

import { createScanMachine, reduceScanMachine } from "../dist/shared/scan-machine.js";
import { executePasteScan } from "../dist/worker/fetch/paste.js";
import { PUBLIC_CONTROL, verifyPublicControl } from "../scripts/verify-public-control.mjs";

const html = "<html><head><title>Links</title></head><body>0 <a href='/links/3/1'>1</a> <a href='/links/3/2'>2</a> </body></html>";
const publicAddress = "93.184.216.34";
function transport(body = html) {
  let tick = 1_000;
  return { resolver: async (hostname) => { assert.equal(hostname, "httpbin.org");
    return [publicAddress]; }, now: () => tick++, fetcher: async (url, init) => {
      assert.equal(url, PUBLIC_CONTROL.url); assert.equal(init.redirect, "manual");
      return new Response(body, { status: 200, headers: { "content-type": "text/html; charset=utf-8" } });
    } };
}
function receipt(operation) {
  let machine = createScanMachine(operation.input);
  for (const entry of operation.journal) machine = reduceScanMachine(machine, entry.fact);
  const effect = machine.pending; assert.equal(effect.kind, "ALLOCATE_IDS");
  const ids = Array.from({ length: effect.count }, (_, index) =>
    (index + 1).toString(16).padStart(32, "0"));
  return reduceScanMachine(machine, { kind: "IDS_ALLOCATED", effect_id: effect.id, ids })
    .exchange.receipt;
}
const observer = { provider: "google_safe_browsing", source: "live", observe: async (request) => ({
  provider: "google_safe_browsing", source: "live", queried_target: request.canonical_target,
  observed_at: request.requested_at, expires_at: null, freshness: "unknown", state: "no_match",
  category: null, confidence: "low", reference: null, error: null,
}) };

test("the frozen control uses production fetch, admission, extraction, and scan behavior", async () => {
  const result = await verifyPublicControl({ now: () => new Date("2026-09-03T00:00:00Z"),
    fetch_seams: transport() });
  assert.deepEqual(result, { contract_id: "httpbin-links-3-0-v1", accepted_targets: 2,
    rejected_candidates: 0, validated_hops: 1, provider_requests: 2, result: "pass" });
});

test("prior special-host and no-anchor controls fail through the production machine", async () => {
  let contacted = false;
  const reserved = await executePasteScan({ mode: "url", url: "https://example.com/" }, {
    now: () => new Date("2026-09-03T00:00:00Z"), provider: observer,
    fetch_seams: { resolver: async () => { contacted = true; return [publicAddress]; },
      fetcher: async () => { contacted = true; return new Response(html); } },
  });
  assert.equal(receipt(reserved).accepted_targets, 0); assert.equal(contacted, false);
  const generic = await executePasteScan({ mode: "url", url: PUBLIC_CONTROL.url }, {
    now: () => new Date("2026-09-03T00:00:00Z"), provider: observer,
    fetch_seams: transport("<!doctype html><title>generic page</title>"),
  });
  assert.equal(receipt(generic).accepted_targets, 0);
});

test("the frozen control fails closed on redirect and occurrence drift", async () => {
  let call = 0, tick = 1_000;
  await assert.rejects(verifyPublicControl({ fetch_seams: {
    resolver: async () => [publicAddress], now: () => tick++, fetcher: async () => {
      call += 1;
      return call === 1 ? new Response(null, { status: 302, headers: { location: "/moved" } }) :
        new Response(html, { status: 200, headers: { "content-type": "text/html" } });
    },
  } }), /control_contract_failed/);
  await assert.rejects(verifyPublicControl({ fetch_seams: transport(
    `${html}<a href="/links/3/1">duplicate</a>`,
  ) }), /control_contract_failed/);
});
