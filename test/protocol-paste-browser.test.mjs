import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { cpSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { isDeepStrictEqual } from "node:util";
import * as serverFetch from "../dist/worker/fetch/fetch-machine.js";
import * as serverScan from "../dist/shared/scan-machine.js";
import { executePasteScan } from "../dist/worker/fetch/paste.js";
import * as browserFetch from "../public/protocol/fetch-machine.generated.js";
import * as browserScan from "../public/protocol/scan-machine.generated.js";
import { oneFieldMutants } from "./support/protocol-mutants.mjs";

const NOW = new Date("2026-09-01T06:30:00.000Z"), LIMITS = { max_url_chars: 2048, max_redirects: 5, max_response_bytes: 200000, operation_ms: 100, total_ms: 500 };
const sha = (value) => createHash("sha256").update(value).digest("hex");
const ids = (count) => Array.from({ length: count }, (_, index) => index.toString(16).padStart(32, "0"));
const headers = { location: { value: null, overflow: false }, "content-type": { value: "text/html", overflow: false }, "content-encoding": { value: null, overflow: false }, "content-length": { value: "2", overflow: false } };
const outcome = (fn) => { try { return ["ok", fn()]; } catch (error) { return [error.constructor.name, error.message]; } };
function fetchRun(api, terminal = "success") {
  const journal = []; let machine = api.createFetchMachine("https://public.example.co/a", LIMITS, 0);
  const facts = terminal === "success" ? [
    { kind: "dns", completed_at: 1, addresses: ["8.8.8.8"], overflow: false, failure: null },
    { kind: "fetch", completed_at: 2, failure: null },
    { kind: "metadata", completed_at: 3, status: 200, headers, failure: null },
    () => ({ kind: "read", completed_at: 4, failure: null, token: machine.pending.token, length: 2, digest: "abcd", valid_utf8: true }),
  ] : [{ kind: "dns", completed_at: 101, addresses: ["8.8.8.8"], overflow: false, failure: null }];
  const states = [machine]; for (const item of facts) { const fact = typeof item === "function" ? item() : item; journal.push(api.journalEntry(machine.pending, fact)); machine = api.reduceFetchMachine(machine, fact); states.push(machine); }
  return { states, journal, result: api.replayFetchMachine("https://public.example.co/a", LIMITS, 0, journal) };
}
function complete(api, operation) {
  let machine = api.createScanMachine(operation.input); const states = [machine], journal = [...operation.journal];
  for (const entry of operation.journal) { machine = api.reduceScanMachine(machine, entry.fact); states.push(machine); }
  const fact = { kind: "IDS_ALLOCATED", effect_id: machine.pending.id, ids: ids(machine.pending.count) };
  journal.push(api.scanJournalEntry(machine.pending, fact)); machine = api.reduceScanMachine(machine, fact); states.push(machine);
  return { states, journal, exchange: api.replayScanMachine(operation.input, journal) };
}
const paste = (count, occurrenceCount = count) => executePasteScan({ mode: "html", base_url: "https://source.example/base", html: Array.from({ length: occurrenceCount }, (_, index) => `<a href="/t-${Math.min(index, count - 1)}#${index}">T${index}</a>`).join("") }, { now: () => NOW });

test("manifest binds the complete sorted source closure and chunk bytes", () => {
  const manifest = JSON.parse(readFileSync("public/protocol/manifest.json", "utf8"));
  assert.deepEqual(Object.keys(manifest), ["schema_version", "generator", "typescript_version", "target", "sources", "chunks"]);
  assert.deepEqual(Object.keys(manifest.sources), Object.keys(manifest.sources).sort((a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b))));
  for (const [name, digest] of Object.entries(manifest.sources)) assert.equal(sha(readFileSync(name)), digest, name);
  for (const chunk of manifest.chunks) {
    const bytes = readFileSync(`public/protocol/${chunk.file}`);
    const tree = chunk.source_paths.map((name) => `${name}\0${manifest.sources[name]}\n`).join("");
    assert.deepEqual([bytes.length, sha(bytes), sha(tree)], [chunk.bytes, chunk.sha256, chunk.source_tree_sha256]);
  }
  assert.deepEqual(manifest.chunks.map(({ id, depends_on }) => [id, depends_on]), [["fetch-machine", []], ["scan-machine", ["fetch-machine"]]]);
});

test("generated modules are browser-safe ES2022 with the frozen export surface", async () => {
  assert.deepEqual(Object.keys(browserFetch), ["createFetchMachine", "journalEntry", "reduceFetchMachine", "replayFetchMachine"]);
  assert.deepEqual(Object.keys(browserScan), ["SCAN_LIMITATIONS", "SCAN_LIMITS", "createScanMachine", "reduceScanMachine", "replayScanMachine", "scanJournalEntry", "verifyScanExchange"]);
  for (const name of ["fetch-machine", "scan-machine"]) {
    const source = readFileSync(`public/protocol/${name}.generated.js`, "utf8");
    assert.doesNotMatch(source, /(?:node:|(?:\.\.\/)*(?:dist|src)\/|\bprocess\b|\bBuffer\b|\beval\s*\(|new Function|\brequire\s*\()/u);
    assert.equal((source.match(/^import /gmu) ?? []).length, name === "scan-machine" ? 1 : 0);
  }
  assert.ok((await import(`../public/protocol/scan-machine.generated.js?${Date.now()}`)).createScanMachine);
});

test("fetch creation, every transition, terminal success, and failure replay have full parity", () => {
  for (const kind of ["success", "timeout"]) {
    const left = fetchRun(serverFetch, kind), right = fetchRun(browserFetch, kind);
    assert.deepEqual(right, left);
    for (const mutant of oneFieldMutants(left.journal)) {
      const server = outcome(() => serverFetch.replayFetchMachine("https://public.example.co/a", LIMITS, 0, mutant.value));
      assert.deepEqual(outcome(() => browserFetch.replayFetchMachine("https://public.example.co/a", LIMITS, 0, mutant.value)), server, mutant.detail);
      if (mutant.kind === "add" || mutant.kind === "delete") assert.notEqual(server[0], "ok", mutant.detail);
    }
  }
});

test("actual immutable URL fetch journals replay without I/O in both generated graphs", async () => {
  let calls = 0;
  const operation = await executePasteScan({ mode: "url", url: "https://public.example.co/a" }, { now: () => NOW, fetch_seams: { now: () => 0, resolver: async () => ["8.8.8.8"], fetcher: async () => (calls += 1, new Response('<a href="/a">A</a>', { headers: { "content-type": "text/html" } })) } });
  assert.equal(calls, 1); const left = complete(serverScan, operation), right = complete(browserScan, operation);
  assert.deepEqual(right, left); assert.equal(calls, 1); assert.ok(Object.isFrozen(operation) && Object.isFrozen(operation.journal));
});

test("actual Paste prefixes preserve full state and exchange parity at result boundaries", async () => {
  for (const count of [0, 1, 15, 16, 17, 32]) {
    const operation = await paste(count, count), left = complete(serverScan, operation), right = complete(browserScan, operation);
    assert.deepEqual(right, left, String(count)); assert.equal(left.exchange.entries.length, count === 0 ? 1 : Math.min(count, 16));
  }
});

test("Paste occurrence boundaries 255/256/257 and deterministic allocation stay identical", async () => {
  for (const count of [255, 256, 257]) {
    const operation = await paste(1, count), left = complete(serverScan, operation), right = complete(browserScan, operation);
    assert.deepEqual(right, left); assert.deepEqual(left.exchange.receipt.occurrence_count, count === 257 ? { kind: "at_least", count: 257 } : { kind: "exact", count });
  }
});

test("systematic nested mutations and coherent claim changes discriminate identically", async () => {
  const operation = await paste(2, 3), run = complete(serverScan, operation);
  const mutations = [
    ...oneFieldMutants(operation.input).map((mutant) => ({ ...mutant, input: mutant.value, journal: run.journal })),
    ...oneFieldMutants(run.journal).map((mutant) => ({ ...mutant, input: operation.input, journal: mutant.value })),
  ];
  for (const mutant of mutations) {
    const server = outcome(() => serverScan.replayScanMachine(mutant.input, mutant.journal));
    assert.deepEqual(outcome(() => browserScan.replayScanMachine(mutant.input, mutant.journal)), server, mutant.detail);
    if (mutant.kind === "add" || mutant.kind === "delete") assert.notEqual(server[0], "ok", mutant.detail);
    if (server[0] === "ok" && !isDeepStrictEqual(server[1], run.exchange)) assert.throws(() => serverScan.verifyScanExchange(mutant.input, mutant.journal, run.exchange), mutant.detail);
  }
  for (const mutant of oneFieldMutants(run.exchange)) { const server = outcome(() => serverScan.verifyScanExchange(operation.input, run.journal, mutant.value)); assert.notEqual(server[0], "ok", mutant.detail); assert.deepEqual(outcome(() => browserScan.verifyScanExchange(operation.input, run.journal, mutant.value)), server, mutant.detail); }
  assert.deepEqual(browserScan.verifyScanExchange(operation.input, run.journal, run.exchange), run.exchange);
});

test("check mode is read-only and rejects stale source and tampered derived artifacts", (t) => {
  const generator = path.resolve("scripts/sync-protocol.mjs"), before = ["fetch-machine.generated.js", "scan-machine.generated.js", "manifest.json"].map((name) => [sha(readFileSync(`public/protocol/${name}`)), statSync(`public/protocol/${name}`).mtimeMs]);
  execFileSync(process.execPath, [generator, "--check"], { env: { ...process.env, TMPDIR: process.env.TMPDIR } });
  assert.deepEqual(["fetch-machine.generated.js", "scan-machine.generated.js", "manifest.json"].map((name) => [sha(readFileSync(`public/protocol/${name}`)), statSync(`public/protocol/${name}`).mtimeMs]), before);
  const root = mkdtempSync(path.join(process.env.TMPDIR ?? os.tmpdir(), "protocol-check-"));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  for (const name of ["package.json", "package-lock.json", "tsconfig.json", "node_modules", "src", "public/protocol"]) cpSync(name, path.join(root, name), { recursive: true });
  const invoke = () => spawnSync(process.execPath, [generator, "--check"], { cwd: root, encoding: "utf8", env: { ...process.env, TMPDIR: process.env.TMPDIR } });
  writeFileSync(path.join(root, "src/shared/canonicalize.ts"), readFileSync(path.join(root, "src/shared/canonicalize.ts"), "utf8") + "\n");
  assert.match(invoke().stderr, /RS-FC-ARTIFACT-STALE/u);
  cpSync("src/shared/canonicalize.ts", path.join(root, "src/shared/canonicalize.ts")); writeFileSync(path.join(root, "public/protocol/fetch-machine.generated.js"), readFileSync(path.join(root, "public/protocol/fetch-machine.generated.js"), "utf8") + " ");
  assert.match(invoke().stderr, /RS-FC-ARTIFACT-TAMPER/u);
});
