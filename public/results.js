import {
  SCAN_LIMITS,
  createScanMachine,
  reduceScanMachine,
  scanJournalEntry,
} from "./protocol/scan-machine.generated.js";

const clone = (value) => structuredClone(value);
function same(left, right) {
  if (Object.is(left, right)) return true;
  if (typeof left !== "object" || left === null || typeof right !== "object" ||
    right === null || Array.isArray(left) !== Array.isArray(right)) return false;
  if (Array.isArray(left)) return left.length === right.length &&
    left.every((item, index) => same(item, right[index]));
  const keys = Object.keys(left).sort();
  const other = Object.keys(right).sort();
  return keys.length === other.length &&
    keys.every((key, index) => key === other[index] && same(left[key], right[key]));
}

const primitive = (value) => ({
  provider: value.provider,
  source: value.source,
  queried_target: value.queried_target,
  observed_at: value.observed_at,
  expires_at: value.expires_at,
  state: value.state,
  category: value.category,
  reference: value.reference,
  error: value.error,
});

function atoms(request) {
  return [
    ...request.candidates.map((candidate) => ({
      index: candidate.provenance.occurrence_index,
      atom: { kind: "ANCHOR", href: candidate.raw_href, href_overflow: false,
        text: candidate.anchor_text, text_overflow: false },
    })),
    ...request.extraction_rejections.map((rejection) => ({
      index: rejection.occurrence_index,
      atom: { kind: "ANCHOR", href: null, href_overflow: true, text: "",
        text_overflow: false },
    })),
  ].sort((left, right) => left.index - right.index).map(({ atom }) => atom);
}

function legacy(receipt, analyzedAt) {
  return {
    mode: "live_page",
    analyzed_at: analyzedAt,
    scan_ids: [...receipt.scan_ids],
    observed_candidates: receipt.occurrence_count.count,
    accepted_targets: receipt.accepted_targets,
    rejected_candidates: receipt.rejected_candidates,
    truncated: receipt.truncated,
    page_evidence_trust: "untrusted",
    targets: receipt.targets.map((target) => ({
      canonical_url: target.canonical_url,
      occurrence_indices: target.occurrences.map(({ occurrence_index }) => occurrence_index),
      anchor_text_variants: [...target.anchor_text_variants],
    })),
    rejections: receipt.rejections.map(({ occurrence_index, reason }) => ({
      occurrence_index, reason,
    })),
  };
}

export async function decodeLiveExchange({ request, receipt, loadResult }) {
  if (typeof receipt !== "object" || receipt === null || !Array.isArray(receipt.scan_ids) ||
    receipt.scan_ids.length > SCAN_LIMITS.results ||
    new Set(receipt.scan_ids).size !== receipt.scan_ids.length || !receipt.scan_ids.every((id) =>
      typeof id === "string" && /^[a-f0-9]{32}$/u.test(id))) {
    throw new TypeError("malformed_response");
  }
  const loaded = await Promise.all(receipt.scan_ids.map(loadResult));
  for (const envelope of loaded) {
    if (typeof envelope !== "object" || envelope === null ||
      !same(Object.keys(envelope).sort(), ["result", "status"]) || envelope.status !== "ok") {
      throw new TypeError("malformed_response");
    }
  }
  const results = loaded.map(({ result }) => result);
  const input = { version: 1, kind: "live_page", analyzed_at: receipt.analyzed_at,
    base_url: request.document_url, document_url: request.document_url };
  let machine = createScanMachine(input);
  let effect = machine.pending;
  let entry = scanJournalEntry(effect,
    { kind: "EXTRACTED", effect_id: effect.id, atoms: atoms(request) });
  machine = reduceScanMachine(machine, entry.fact);
  effect = machine.pending;
  if (effect?.kind === "OBSERVE_PROVIDER") {
    const requests = effect.batch ?? [effect];
    const observations = requests.map((_, index) => primitive(
      results[index]?.provider_observations?.[0] ?? {}));
    const fact = effect.batch === undefined
      ? { kind: "PROVIDER_OBSERVED", effect_id: effect.id, observation: observations[0] }
      : { kind: "PROVIDER_OBSERVED", effect_id: effect.id,
          observation: observations[0], batch: observations };
    entry = scanJournalEntry(effect, fact);
    machine = reduceScanMachine(machine, entry.fact);
  }
  effect = machine.pending;
  if (effect?.kind !== "ALLOCATE_IDS") throw new TypeError("malformed_response");
  const receiptId = Array.from({ length: SCAN_LIMITS.results + 1 }, (_, index) =>
    index.toString(16).padStart(32, "0")).find((id) => !receipt.scan_ids.includes(id));
  if (receiptId === undefined) throw new TypeError("malformed_response");
  entry = scanJournalEntry(effect, { kind: "IDS_ALLOCATED", effect_id: effect.id,
    ids: [receiptId, ...receipt.scan_ids] });
  machine = reduceScanMachine(machine, entry.fact);
  const exchange = machine.exchange;
  if (exchange === null || !same(legacy(exchange.receipt, receipt.analyzed_at), receipt) ||
    !same(exchange.entries.map(({ result }) => result), results)) {
    throw new TypeError("malformed_response");
  }
  return clone(exchange);
}

export function presentExchange(exchange) {
  return {
    mode: exchange.receipt.mode,
    accepted_targets: exchange.receipt.accepted_targets,
    rejected_candidates: exchange.receipt.rejected_candidates,
    truncated: exchange.receipt.truncated,
    occurrence_count: clone(exchange.receipt.occurrence_count),
    targets: clone(exchange.receipt.targets),
    rejections: clone(exchange.receipt.rejections),
    results: exchange.entries.map(({ result }) => clone(result)),
  };
}

const appendText = (document, parent, tag, value) => {
  const node = document.createElement(tag);
  node.textContent = String(value);
  parent.append(node);
};

export function renderExchange(document, container, exchange) {
  container.replaceChildren();
  const view = presentExchange(exchange);
  appendText(document, container, "p",
    `${view.accepted_targets} accepted; ${view.rejected_candidates} rejected`);
  for (const target of view.targets) {
    const section = document.createElement("section");
    appendText(document, section, "h3", target.canonical_url);
    for (const occurrence of target.occurrences) {
      appendText(document, section, "p",
        `Occurrence ${occurrence.occurrence_index}: ${occurrence.anchor_text} (${occurrence.raw_href})`);
    }
    container.append(section);
  }
  for (const rejection of view.rejections) {
    appendText(document, container, "p",
      `Rejected occurrence ${rejection.occurrence_index}: ${rejection.reason}`);
  }
  for (const result of view.results) {
    const section = document.createElement("section");
    appendText(document, section, "h3", result.canonical_target ?? result.analysis_state);
    appendText(document, section, "p",
      `${result.risk_label} · ${result.analysis_state} · ${result.confidence}`);
    for (const evidence of [...result.supporting_evidence,
      ...result.contradicting_evidence]) {
      appendText(document, section, "p",
        `${evidence.source}: ${evidence.category} — ${evidence.target}`);
    }
    for (const limitation of result.limitations) {
      appendText(document, section, "p", limitation);
    }
    container.append(section);
  }
  return view;
}
