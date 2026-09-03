import { pathToFileURL } from "node:url";
import { resolve } from "node:path";

import { executePasteScan } from "../dist/worker/fetch/paste.js";
import { createScanMachine, reduceScanMachine } from "../dist/shared/scan-machine.js";

export const PUBLIC_CONTROL = Object.freeze({
  id: "httpbingo-links-3-0-v1",
  url: "https://httpbingo.org/links/3/0",
  targets: Object.freeze([
    "https://httpbingo.org/links/3/1",
    "https://httpbingo.org/links/3/2",
  ]),
});

const fail = (code) => { throw new TypeError(code); };
const same = (left, right) => left.length === right.length &&
  left.every((value, index) => value === right[index]);

export async function verifyPublicControl(dependencies = {}) {
  const requested = [];
  const provider = {
    provider: "google_safe_browsing", source: "live",
    async observe(request) {
      requested.push(request.canonical_target);
      return { provider: "google_safe_browsing", source: "live",
        queried_target: request.canonical_target, observed_at: request.requested_at,
        expires_at: null, freshness: "unknown", state: "not_configured", category: null,
        confidence: "low", reference: null, error: "not_configured" };
    },
  };
  const operation = await executePasteScan({ mode: "url", url: PUBLIC_CONTROL.url },
    { ...dependencies, provider });
  let machine = createScanMachine(operation.input);
  for (const entry of operation.journal) machine = reduceScanMachine(machine, entry.fact);
  const allocation = machine.pending;
  if (allocation?.kind !== "ALLOCATE_IDS") fail("control_incomplete");
  const ids = Array.from({ length: allocation.count }, (_, index) =>
    (index + 1).toString(16).padStart(32, "0"));
  machine = reduceScanMachine(machine,
    { kind: "IDS_ALLOCATED", effect_id: allocation.id, ids });
  const receipt = machine.exchange?.receipt;
  const targets = receipt?.targets.map(({ canonical_url }) => canonical_url).sort() ?? [];
  const expected = [...PUBLIC_CONTROL.targets].sort();
  if (receipt?.mode !== "paste_url" || receipt.accepted_targets !== 2 ||
    receipt.rejected_candidates !== 0 || receipt.unscannable_reason !== null ||
    receipt.truncated || !same(targets, expected) || !same([...requested].sort(), expected) ||
    !Array.isArray(receipt.fetch_evidence?.validated_hops) ||
    receipt.fetch_evidence.validated_hops.length === 0 ||
    receipt.fetch_evidence.validated_hops.some(({ hostname, address_count }) =>
      hostname !== "httpbingo.org" || !Number.isSafeInteger(address_count) || address_count < 1)) {
    fail("control_contract_failed");
  }
  return Object.freeze({ contract_id: PUBLIC_CONTROL.id, accepted_targets: 2,
    rejected_candidates: 0, validated_hops: receipt.fetch_evidence.validated_hops.length,
    provider_requests: requested.length, result: "pass" });
}

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  verifyPublicControl().then((result) => console.log(JSON.stringify(result)), () => {
    console.error("PUBLIC_CONTROL_FAIL"); process.exitCode = 1;
  });
}
