import assert from "node:assert/strict";
import test from "node:test";
import { executePasteScan } from "../dist/worker/fetch/paste.js";
import { executeLiveScan } from "../dist/worker/live.js";
import { FixtureProviderAdapter } from "../dist/worker/providers/fixture.js";
import { decodeReceipt, decodeResult } from "../public/protocol.js";
test("Paste and Live preserve equal downstream facts apart from provenance", async () => {
  const now = "2026-09-01T12:00:00.000Z"; const results = [[], []];
  const provider = new FixtureProviderAdapter({ outcome: "no_match", observed_at: now,
    expires_at: "2026-09-01T12:30:00.000Z" });
  const id = "a".repeat(32); const dependencies = (index) => ({ now: () => new Date(now), provider, store: async (result) => {
    results[index].push(structuredClone({ ...result, scan_id: id })); return id; } });
  const paste = await executePasteScan({ mode: "html", html: "<a href='./evidence'>Same</a>",
    base_url: "https://watch.example/reference" }, dependencies(0));
  const live = await executeLiveScan({ document_url: "https://watch.example/reference", observed_at: now,
    candidates: [{ raw_href: "./evidence", anchor_text: "Same", base_url: "https://watch.example/reference",
      provenance: { source: "live_page", document_url: "https://watch.example/reference",
        occurrence_index: 0, extracted_at: now } }], extraction_rejections: [] }, dependencies(1));
  const comparable = ({ mode: _mode, ...result }) => result; assert.deepEqual(comparable(results[0][0]), comparable(results[1][0]));
  assert.equal(results[0][0].outcome, "no_known_match_medium");
  assert.equal(decodeReceipt({ kind: "paste_html" }, paste).mode, "paste_html"); assert.equal(decodeReceipt({ kind: "live_page", observedCandidates: 1 }, live).mode, "live_page");
  for (const item of results) assert.equal(decodeResult({ scanId: id, mode: item[0].mode }, { status: "ok", result: item[0] }).risk, "no_known_match");
});
