import assert from "node:assert/strict";
import test from "node:test";
import { extractHtmlLinkCandidates } from "../dist/shared/extract-html.js";
import { SCAN_LIMITATIONS, createScanMachine, reduceScanMachine, replayScanMachine, scanJournalEntry, verifyScanExchange } from "../dist/shared/scan-machine.js";
import { safeFetchHtml } from "../dist/worker/fetch/safe-fetch.js";
import { captureRealProducerCorpus } from "./support/real-producer-corpus.mjs";
import { oneFieldMutants } from "./support/protocol-mutants.mjs";

const NOW = "2026-09-01T06:30:00.000Z";
const OBSERVED = "2026-09-01T06:00:00.000Z";
const EXPIRES = "2026-09-01T07:00:00.000Z";
const LIMITS = { max_url_chars: 2048, max_redirects: 5, max_response_bytes: 200000, operation_ms: 3000, total_ms: 8000 };
const htmlInput = (html = "", base_url = "https://source.example/base") => ({ version: 1, kind: "paste_html", analyzed_at: NOW, base_url, html });
const anchor = (href, text = "ordinary", extra = {}) => ({ kind: "ANCHOR", href, href_overflow: false, text, text_overflow: false, ...extra });
const observed = (target, extra = {}) => ({
  provider: "google_safe_browsing",
  source: "fixture",
  queried_target: target,
  observed_at: OBSERVED,
  expires_at: EXPIRES,
  state: "no_match",
  category: null,
  reference: "https://provider.example/reference",
  error: null,
  ...extra,
});
const ids = (count) => Array.from({ length: count }, (_, index) => index.toString(16).padStart(32, "0"));

function apply(machine, fact, journal) {
  const entry = scanJournalEntry(machine.pending, fact);
  journal.push(entry);
  return reduceScanMachine(machine, fact);
}

function drive(input, atoms, observationFor = (effect) => observed(effect.canonical_target)) {
  const journal = [];
  let machine = createScanMachine(input);
  if (machine.pending.kind === "EXTRACT_HTML") machine = apply(machine, { kind: "EXTRACTED", effect_id: machine.pending.id, atoms }, journal);
  while (machine.pending.kind === "OBSERVE_PROVIDER") {
    const effect = machine.pending;
    machine = apply(machine, { kind: "PROVIDER_OBSERVED", effect_id: effect.id, observation: observationFor(effect) }, journal);
  }
  assert.equal(machine.pending.kind, "ALLOCATE_IDS");
  machine = apply(machine, { kind: "IDS_ALLOCATED", effect_id: machine.pending.id, ids: ids(machine.pending.count) }, journal);
  return { machine, journal, exchange: machine.exchange };
}

async function recordedFetch(url, fetcher) {
  const journal = [];
  const result = await safeFetchHtml(url, {
    now: () => 0,
    resolver: async () => ["93.184.216.34"],
    fetcher,
    record: (entry) => journal.push(entry),
  });
  return { result, journal, input: { version: 1, kind: "paste_url", analyzed_at: NOW, request_url: url, fetch: { started: 0, limits: LIMITS, journal } } };
}

test("closed input authenticates source and schedules only extraction or final allocation", async () => {
  const inline = createScanMachine(htmlInput("<a>inert</a>"));
  assert.equal(inline.phase, "AWAIT_EXTRACT");
  assert.deepEqual(inline.pending, {
    kind: "EXTRACT_HTML",
    id: 1,
    source: "paste_html",
    base_url: "https://source.example/base",
    document_url: "https://source.example/base",
    extracted_at: NOW,
    body: { kind: "inline_html", html: "<a>inert</a>" },
    limits: { occurrences: 256, href_chars: 2048, anchor_text_chars: 512 },
  });
  assert.ok(Object.isFrozen(inline) && Object.isFrozen(inline.pending) && Object.isFrozen(inline.context.input));
  for (const invalid of [
    { ...htmlInput(), surprise: true },
    { ...htmlInput(), version: 2 },
    { ...htmlInput(), analyzed_at: "2026-09-01T06:30:00Z" },
    { ...htmlInput(), html: "x".repeat(205001) },
    { ...htmlInput(), base_url: "data:text/plain,no" },
  ]) {
    if (invalid.base_url === "data:text/plain,no") assert.equal(createScanMachine(invalid).pending.kind, "ALLOCATE_IDS");
    else assert.throws(() => createScanMachine(invalid));
  }
  const tooLarge = createScanMachine(htmlInput("x".repeat(200001)));
  assert.deepEqual([tooLarge.pending.kind, tooLarge.pending.count, tooLarge.context.outcomes[0].reason], ["ALLOCATE_IDS", 2, "input_too_large"]);

  const success = await recordedFetch("https://public.example.co/success", async () => new Response("<p>bounded</p>", { headers: { "content-type": "text/html", "content-length": "14" } }));
  assert.equal(success.result.ok, true);
  const urlMachine = createScanMachine(success.input);
  assert.deepEqual(urlMachine.pending.body, { kind: "fetch_body", token: success.result.token ?? success.journal.at(-1).fact.token, length: 14, digest: success.journal.at(-1).fact.digest });
  assert.deepEqual(urlMachine.context.evidence, success.result.evidence);
});

test("fetch journals are closed, effect-bound, exactly replayed, and failures become source facts", async () => {
  const failed = await recordedFetch("https://loop.example.co/a", async (url) => new Response(null, { status: 302, headers: { location: url.endsWith("/a") ? "/b" : "/a" } }));
  assert.equal(failed.result.ok, false);
  assert.equal(failed.result.reason, "redirect_loop");
  const run = drive(failed.input, []);
  assert.deepEqual([run.exchange.receipt.unscannable_reason, run.exchange.receipt.fetch_evidence.redirect_chain], ["redirect_loop", ["https://loop.example.co/b", "https://loop.example.co/a"]]);
  assert.equal(run.journal.length, 1, "source failure has no extraction/provider effect");

  const valid = structuredClone(failed.input);
  for (const mutate of [
    (value) => value.fetch.journal.pop(),
    (value) => value.fetch.journal.push(structuredClone(value.fetch.journal[0])),
    (value) => value.fetch.journal.reverse(),
    (value) => {
      value.fetch.journal[0].effect.id += 1;
    },
    (value) => {
      value.fetch.journal[0].fact.extra = true;
    },
    (value) => {
      value.fetch.summary = failed.result;
    },
  ]) {
    const changed = structuredClone(valid);
    mutate(changed);
    assert.throws(() => createScanMachine(changed));
  }
  const afterDone = structuredClone(valid);
  afterDone.fetch.journal.push(structuredClone(afterDone.fetch.journal.at(-1)));
  assert.throws(() => createScanMachine(afterDone));
});

test("accepted literal and trailing-dot fetch traces replay without a second address policy", async () => {
  let literalResolutions = 0;
  const literalJournal = [];
  const literalResult = await safeFetchHtml("https://8.8.8.8/page", {
    now: () => 0,
    resolver: async () => {
      literalResolutions += 1;
      return ["93.184.216.34"];
    },
    fetcher: async () => new Response("ok", { headers: { "content-type": "text/html" } }),
    record: (entry) => literalJournal.push(entry),
  });
  assert.equal(literalResult.ok, true);
  assert.equal(literalResolutions, 0);
  assert.equal(
    createScanMachine({ version: 1, kind: "paste_url", analyzed_at: NOW, request_url: "https://8.8.8.8/page", fetch: { started: 0, limits: LIMITS, journal: literalJournal } }).pending.kind,
    "EXTRACT_HTML",
  );
  const impossible = structuredClone(literalJournal);
  impossible[0].effect = { kind: "dns", hostname: "8.8.8.8", deadline: 3000, id: 1, issued_at: 0 };
  impossible[0].fact = { kind: "dns", completed_at: 0, addresses: ["8.8.8.8"], overflow: false, failure: null };
  assert.throws(() => createScanMachine({ version: 1, kind: "paste_url", analyzed_at: NOW, request_url: "https://8.8.8.8/page", fetch: { started: 0, limits: LIMITS, journal: impossible } }));

  const dotted = await recordedFetch("https://public.example.co./page", async () => new Response("ok", { headers: { "content-type": "text/html" } }));
  assert.equal(dotted.result.ok, true);
  const dottedMachine = createScanMachine(dotted.input);
  assert.equal(dottedMachine.pending.document_url, "https://public.example.co./page");
});

test("occurrence boundary is exact at 255/256 and lower-bound at 257 with illegal sentinels rejected", () => {
  for (const count of [255, 256]) {
    const atoms = Array.from({ length: count }, (_, index) => anchor(`/same#${index}`, `T${index}`));
    const { exchange } = drive(htmlInput(), atoms);
    assert.deepEqual(exchange.receipt.occurrence_count, { kind: "exact", count });
    assert.equal(exchange.receipt.targets[0].occurrences.length, count);
    assert.equal(exchange.receipt.truncated, false);
  }
  const bounded = Array.from({ length: 256 }, (_, index) => anchor(`/same#${index}`, `T${index}`));
  bounded.push({ kind: "OCCURRENCE_OVERFLOW" });
  const { exchange } = drive(htmlInput(), bounded);
  assert.deepEqual(exchange.receipt.occurrence_count, { kind: "at_least", count: 257 });
  assert.equal(exchange.receipt.targets[0].occurrences.length, 256);
  assert.ok(exchange.entries[0].result.limitations.includes(SCAN_LIMITATIONS.occurrences));
  assert.equal(JSON.stringify(exchange).includes("T256"), false);

  const invalid = [
    [{ kind: "OCCURRENCE_OVERFLOW" }],
    [...bounded, { kind: "OCCURRENCE_OVERFLOW" }],
    [...bounded.slice(0, -1), anchor("/257")],
    [...bounded.slice(0, -1), { kind: "OCCURRENCE_OVERFLOW" }, anchor("/after")],
  ];
  for (const atoms of invalid) {
    const machine = createScanMachine(htmlInput());
    assert.throws(() => reduceScanMachine(machine, { kind: "EXTRACTED", effect_id: 1, atoms }));
  }
});

test("extraction primitives enforce exact href, text, and overflow-marker bounds", () => {
  const machine = createScanMachine(htmlInput());
  assert.doesNotThrow(() => reduceScanMachine(machine, { kind: "EXTRACTED", effect_id: 1, atoms: [anchor("h".repeat(2048), "t".repeat(512))] }));
  for (const atom of [
    anchor("h".repeat(2049)),
    anchor("/ok", "t".repeat(513)),
    anchor("/bytes", "hidden", { href_overflow: true }),
    anchor(null, "missing marker"),
    { kind: "OCCURRENCE_OVERFLOW", extra: true },
  ]) {
    assert.throws(() => reduceScanMachine(machine, { kind: "EXTRACTED", effect_id: 1, atoms: [atom] }));
  }
  assert.doesNotThrow(() => reduceScanMachine(machine, { kind: "EXTRACTED", effect_id: 1, atoms: [anchor(null, "bounded", { href_overflow: true })] }));
});

test("href/text markers, fragments, A-B-A, rejections, and first-occurrence ordinals are machine-owned", () => {
  const atoms = [
    anchor("/a#first", "First"),
    anchor("mailto:x@example.test", "Mail"),
    anchor("/b", "B"),
    anchor("/a#last", "Second", { text_overflow: true }),
    anchor(null, "hidden", { href_overflow: true }),
  ];
  const { exchange, journal } = drive(htmlInput(), atoms);
  assert.deepEqual(
    journal.filter(({ effect }) => effect.kind === "OBSERVE_PROVIDER").map(({ effect }) => [effect.target_ordinal, effect.canonical_target]),
    [
      [0, "https://source.example/a"],
      [1, "https://source.example/b"],
    ],
  );
  assert.deepEqual(
    exchange.receipt.targets.map(({ target_ordinal, canonical_url }) => [target_ordinal, canonical_url]),
    [
      [0, "https://source.example/a"],
      [1, "https://source.example/b"],
    ],
  );
  assert.deepEqual(
    exchange.receipt.targets[0].occurrences.map(({ occurrence_index }) => occurrence_index),
    [0, 3],
  );
  assert.deepEqual(exchange.receipt.targets[0].anchor_text_variants, ["First", "Second"]);
  assert.deepEqual(
    exchange.receipt.rejections.map(({ rejection_ordinal, occurrence_index, reason }) => [rejection_ordinal, occurrence_index, reason]),
    [
      [0, 1, "unsupported_scheme"],
      [1, 4, "url_too_long"],
    ],
  );
  assert.deepEqual(
    exchange.entries.map(({ outcome }) => outcome.kind),
    ["target", "target", "rejection", "rejection"],
  );
  assert.ok(exchange.entries[0].result.limitations.includes(SCAN_LIMITATIONS.anchor_text));
  assert.equal(exchange.entries[1].result.limitations.includes(SCAN_LIMITATIONS.anchor_text), false);
});

test("effect cardinalities are exact at 0/1/15/16/17/32 and allocation is sole final effect", () => {
  for (const count of [0, 1, 15, 16, 17, 32]) {
    const atoms = Array.from({ length: count }, (_, index) => anchor(`/target-${index}`));
    const { exchange, journal } = drive(htmlInput(), atoms);
    const providers = journal.filter(({ effect }) => effect.kind === "OBSERVE_PROVIDER");
    const allocations = journal.filter(({ effect }) => effect.kind === "ALLOCATE_IDS");
    const retained = count === 0 ? 1 : Math.min(count, 16);
    assert.deepEqual([providers.length, allocations.length, allocations[0].effect.count, exchange.entries.length], [Math.min(count, 16), 1, 1 + retained, retained], String(count));
    assert.equal(journal.at(-1).effect.kind, "ALLOCATE_IDS");
    assert.equal(exchange.receipt.accepted_targets, count);
    assert.equal(exchange.receipt.truncated, count > 16);
    if (count > 16) assert.ok(exchange.entries.every(({ result }) => result.limitations.includes(SCAN_LIMITATIONS.results)));
  }
});

test("provider primitives bind exactly while semantic malformation is conservatively re-derived", () => {
  const cases = [
    [observed("https://source.example/a", { state: "match", category: "social_engineering" }), "known_malicious", "complete"],
    [observed("https://source.example/a"), "no_known_match", "complete"],
    [observed("https://source.example/a", { state: "error", expires_at: null, category: null, error: "timeout" }), "unknown", "provider_error"],
    [observed("https://source.example/a", { state: "not_configured", expires_at: null, category: null, error: "not_configured" }), "unknown", "provider_error"],
    [observed("https://source.example/a", { expires_at: OBSERVED }), "unknown", "stale"],
    [observed("https://source.example/a", { state: "match", category: "invented" }), "unknown", "provider_error"],
  ];
  for (const [observation, label, state] of cases) {
    const { exchange } = drive(htmlInput(), [anchor("/a")], () => observation);
    assert.deepEqual([exchange.entries[0].result.risk_label, exchange.entries[0].result.analysis_state], [label, state]);
    if (observation.category === "invented") assert.equal(exchange.entries[0].result.provider_observations[0].error, "malformed_response");
  }
  const machine = reduceScanMachine(createScanMachine(htmlInput()), { kind: "EXTRACTED", effect_id: 1, atoms: [anchor("/a")] });
  const good = { kind: "PROVIDER_OBSERVED", effect_id: machine.pending.id, observation: observed(machine.pending.canonical_target) };
  for (const bad of [
    { ...good, effect_id: 99 },
    { ...good, extra: true },
    { ...good, observation: { ...good.observation, queried_target: "https://other.example/" } },
    { ...good, observation: { ...good.observation, freshness: "fresh" } },
  ])
    assert.throws(() => reduceScanMachine(machine, bad));
});

test("ID vector and complete exchange are position-bound, closed, immutable, and deterministic", () => {
  const first = drive(htmlInput(), [anchor("/a"), anchor("mailto:x@y")]);
  assert.equal(first.exchange.receipt.receipt_id, ids(4)[0]);
  assert.deepEqual(
    first.exchange.receipt.scan_ids,
    first.exchange.entries.map(({ result_id }) => result_id),
  );
  assert.ok(first.exchange.entries.every(({ result_id, result }) => result_id === result.scan_id));
  assert.deepEqual(replayScanMachine(htmlInput(), first.journal), first.exchange);
  assert.deepEqual(verifyScanExchange(htmlInput(), first.journal, first.exchange), first.exchange);
  assert.throws(() => {
    first.exchange.receipt.scan_ids.push("f".repeat(32));
  }, TypeError);

  const allocationMachine = (() => {
    let machine = createScanMachine(htmlInput());
    machine = reduceScanMachine(machine, { kind: "EXTRACTED", effect_id: 1, atoms: [] });
    return machine;
  })();
  for (const vector of [["a".repeat(32)], ["a".repeat(32), "a".repeat(32)], ["A".repeat(32), "b".repeat(32)], ["z".repeat(32), "b".repeat(32)], ids(3)]) {
    assert.throws(() => reduceScanMachine(allocationMachine, { kind: "IDS_ALLOCATED", effect_id: allocationMachine.pending.id, ids: vector }));
  }
  const mutants = oneFieldMutants(first.exchange, { boundaries: [0, 1, 15, 16, 17, 256, 257] });
  assert.ok(mutants.length > 200);
  for (const mutant of mutants) assert.throws(() => verifyScanExchange(htmlInput(), first.journal, mutant.value), `${mutant.kind}:${mutant.path.join(".")}`);
  const coherent = structuredClone(first.exchange);
  coherent.receipt.receipt_id = "f".repeat(32);
  coherent.receipt.scan_ids = coherent.receipt.scan_ids.map(() => "e".repeat(32));
  coherent.entries.forEach((entry) => {
    entry.result_id = "e".repeat(32);
    entry.result.scan_id = "e".repeat(32);
  });
  assert.throws(() => verifyScanExchange(htmlInput(), first.journal, coherent));
});

test("systematic scan transcript mutations cannot preserve the original exchange", () => {
  const input = htmlInput("primitive input remains unchanged");
  const before = structuredClone(input);
  const valid = drive(input, [anchor("/a", "https://display.example/login")]);
  let checked = 0;
  for (let index = 0; index < valid.journal.length; index += 1) {
    for (const mutant of oneFieldMutants(valid.journal[index], { boundaries: [0, 1, 2, 15, 16, 17, 256, 257] })) {
      const journal = structuredClone(valid.journal);
      journal[index] = mutant.value;
      let changed;
      try {
        changed = replayScanMachine(input, journal);
      } catch (error) {
        assert.ok(error instanceof TypeError || error instanceof RangeError);
        checked += 1;
        continue;
      }
      assert.notDeepEqual(changed, valid.exchange, `${index}:${mutant.kind}:${mutant.path.join(".")}`);
      assert.throws(() => verifyScanExchange(input, journal, valid.exchange));
      checked += 1;
    }
  }
  assert.ok(checked > 100);
  assert.deepEqual(input, before);
  assert.deepEqual(replayScanMachine(input, valid.journal), valid.exchange);
});

test("real producer corpus primitives retain grouping and non-ID analysis without mutation", async () => {
  const corpus = await captureRealProducerCorpus();
  const before = structuredClone(corpus);
  const request = corpus.contexts.paste_html.request;
  const candidates = extractHtmlLinkCandidates(request.html, { base_url: request.base_url, document_url: request.base_url, extracted_at: NOW });
  const atoms = candidates.map(({ raw_href, anchor_text }) => anchor(raw_href, anchor_text));
  const primitive = (({ provider, source, queried_target, observed_at, expires_at, state, category, reference, error }) => ({
    provider,
    source,
    queried_target,
    observed_at,
    expires_at,
    state,
    category,
    reference,
    error,
  }))(corpus.outputs.provider.match);
  const { exchange } = drive(htmlInput(request.html, request.base_url), atoms, (effect) => ({ ...primitive, queried_target: effect.canonical_target }));
  assert.deepEqual([exchange.receipt.accepted_targets, exchange.receipt.rejected_candidates], [corpus.outputs.paste_html.accepted_targets, corpus.outputs.paste_html.rejected_candidates]);
  assert.deepEqual(
    exchange.receipt.targets.map(({ canonical_url, occurrences, anchor_text_variants }) => ({
      canonical_url,
      occurrence_indices: occurrences.map(({ occurrence_index }) => occurrence_index),
      anchor_text_variants,
    })),
    [
      { canonical_url: "https://source.example/same", occurrence_indices: [0, 1], anchor_text_variants: ["First", "Second"] },
      { canonical_url: "https://target.example/path", occurrence_indices: [3], anchor_text_variants: ["https://display.example/login"] },
    ],
  );
  const actual = corpus.events.stores.filter(({ operation }) => operation === "paste_html").map(({ stored }) => ({ ...stored, scan_id: "ignored" }));
  const derived = exchange.entries.map(({ result }) => ({ ...result, scan_id: "ignored" }));
  assert.deepEqual(derived, actual);
  assert.deepEqual(corpus, before);
});
