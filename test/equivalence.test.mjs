import assert from "node:assert/strict";
import test from "node:test";

import { executePasteScan } from "../dist/worker/fetch/paste.js";
import { executeLiveScan } from "../dist/worker/live.js";
import { FixtureProviderAdapter } from "../dist/worker/providers/fixture.js";

test("equivalent Paste and rendered-DOM candidates have identical downstream semantics", async () => {
  const now = "2026-09-01T12:00:00.000Z";
  const provider = new FixtureProviderAdapter({
    outcome: "no_match",
    observed_at: now,
    expires_at: "2026-09-01T12:30:00.000Z",
  });
  const pasteResults = [];
  const liveResults = [];
  const paste = await executePasteScan({
    mode: "html",
    html: "<a href='./evidence#paste'>Same evidence</a>",
    base_url: "https://watch.example/reference",
  }, {
    now: () => new Date(now),
    provider,
    store: async (result) => { pasteResults.push(structuredClone(result)); return "a".repeat(32); },
  });
  const live = await executeLiveScan({
    document_url: "https://watch.example/reference",
    observed_at: now,
    candidates: [{
      raw_href: "./evidence#live",
      anchor_text: "Same evidence",
      base_url: "https://watch.example/reference",
      provenance: {
        source: "live_page", document_url: "https://watch.example/reference",
        occurrence_index: 0, extracted_at: now,
      },
    }],
    extraction_rejections: [],
  }, {
    now: () => new Date(now),
    provider,
    store: async (result) => { liveResults.push(structuredClone(result)); return "b".repeat(32); },
  });

  assert.equal(paste.accepted_targets, live.accepted_targets);
  assert.equal(paste.rejected_candidates, live.rejected_candidates);
  assert.equal(pasteResults.length, 1);
  assert.equal(liveResults.length, 1);
  const withoutOrigin = ({ mode: _mode, ...result }) => result;
  assert.deepEqual(withoutOrigin(pasteResults[0]), withoutOrigin(liveResults[0]));
  assert.equal(pasteResults[0].risk_label, "no_known_match");
});
