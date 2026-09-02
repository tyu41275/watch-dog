import assert from "node:assert/strict";
import test from "node:test";
import {
  createFetchMachine, journalEntry, reduceFetchMachine, replayFetchMachine,
} from "../dist/worker/fetch/fetch-machine.js";

const LIMITS = { max_url_chars: 2_048, max_redirects: 5, max_response_bytes: 200_000, operation_ms: 100, total_ms: 500 };
const headers = (values = {}) => Object.fromEntries(Object.entries({
  location: null, "content-type": "text/html", "content-encoding": null, "content-length": null, ...values,
}).map(([name, value]) => [name, { value, overflow: false }]));
function apply(machine, fact, entries = []) {
  entries.push(journalEntry(machine.pending, fact));
  return reduceFetchMachine(machine, fact);
}

test("machine admits without effects only when safe and keeps DNS disposition pure", () => {
  for (const input of ["https://./", "http://127.0.0.1/", "https://localhost./"]) {
    const machine = createFetchMachine(input, LIMITS, 0);
    assert.equal(machine.pending, null, input);
    assert.equal(machine.terminal.ok, false, input);
  }
  assert.equal(createFetchMachine("https://8.8.8.8/", LIMITS, 0).pending.kind, "fetch");
  for (const count of [0, 1, 32, 33, 34]) {
    let machine = createFetchMachine("https://public.example.co/", LIMITS, 0);
    assert.equal(machine.pending.kind, "dns");
    machine = apply(machine, { kind: "dns", completed_at: 1, addresses: Array(Math.min(count, 33)).fill("8.8.8.8"), overflow: count > 32, failure: null });
    assert.equal(count === 1 || count === 32 ? machine.pending.kind : machine.terminal.reason, count === 1 || count === 32 ? "fetch" : "dns_failure", String(count));
  }
});

test("journal is immutable, body-free, exactly replayable, and effect-bound", () => {
  const entries = [];
  let machine = createFetchMachine("https://public.example.co/start", LIMITS, 0);
  machine = apply(machine, { kind: "dns", completed_at: 1, addresses: ["8.8.8.8", "2001:4860:4860::8888"], overflow: false, failure: null }, entries);
  machine = apply(machine, { kind: "fetch", completed_at: 2, failure: null }, entries);
  machine = apply(machine, { kind: "metadata", completed_at: 3, status: 200, headers: headers({ "content-length": "4" }), failure: null }, entries);
  const token = machine.pending.token;
  machine = apply(machine, { kind: "read", completed_at: 4, failure: null, token, length: 4, digest: "deadbeef", valid_utf8: true }, entries);
  assert.equal(machine.terminal.ok, true);
  assert.deepEqual(replayFetchMachine("https://public.example.co/start", LIMITS, 0, entries), machine.terminal);
  assert.equal(JSON.stringify(entries).includes("body"), false);
  assert.throws(() => { entries[0].fact.addresses.push("1.1.1.1"); }, TypeError);
  const forged = structuredClone(entries); forged[1].effect.id += 1;
  assert.throws(() => replayFetchMachine("https://public.example.co/start", LIMITS, 0, forged), /effect mismatch/);
  assert.throws(() => replayFetchMachine("https://public.example.co/start", LIMITS, 0, entries.slice(0, -1)), /incomplete/);
});

const records = (value, path = [], found = []) => {
  if (typeof value !== "object" || value === null) return found;
  if (!Array.isArray(value)) found.push(path);
  for (const [key, child] of Object.entries(value)) records(child, [...path, key], found);
  return found;
};
const at = (value, path) => path.reduce((parent, key) => parent[key], value);
function oneFieldMutants(value) {
  const mutants = [];
  for (const path of records(value)) {
    const original = at(value, path);
    for (const key of Object.keys(original)) {
      const mutant = structuredClone(value); delete at(mutant, path)[key]; mutants.push(mutant);
    }
    const mutant = structuredClone(value); at(mutant, path).unknown_field = true; mutants.push(mutant);
  }
  return mutants;
}

test("every systematic unknown and missing journal field rejects for every effect and fact variant", () => {
  const entries = [];
  let machine = createFetchMachine("https://public.example.co/start", LIMITS, 0);
  machine = apply(machine, { kind: "dns", completed_at: 1, addresses: ["8.8.8.8"], overflow: false, failure: null }, entries);
  machine = apply(machine, { kind: "fetch", completed_at: 2, failure: null }, entries);
  machine = apply(machine, { kind: "metadata", completed_at: 3, status: 302, headers: headers({ location: "/end" }), failure: null }, entries);
  machine = apply(machine, { kind: "discard", completed_at: 4 }, entries);
  machine = apply(machine, { kind: "dns", completed_at: 5, addresses: ["8.8.4.4"], overflow: false, failure: null }, entries);
  machine = apply(machine, { kind: "fetch", completed_at: 6, failure: null }, entries);
  machine = apply(machine, { kind: "metadata", completed_at: 7, status: 200, headers: headers({ "content-length": "4" }), failure: null }, entries);
  machine = apply(machine, { kind: "read", completed_at: 8, failure: null, token: machine.pending.token, length: 4, digest: "deadbeef", valid_utf8: true }, entries);
  const expected = replayFetchMachine("https://public.example.co/start", LIMITS, 0, entries);
  assert.equal(expected.ok, true);
  assert.deepEqual([...new Set(entries.map(({ effect }) => effect.kind))].sort(), ["discard", "dns", "fetch", "metadata", "read"]);
  const mutants = oneFieldMutants(entries); assert.equal(mutants.length, 157);
  for (const mutant of mutants) assert.throws(() => replayFetchMachine("https://public.example.co/start", LIMITS, 0, mutant), TypeError);

  const pending = createFetchMachine("https://public.example.co/", LIMITS, 0);
  const fact = { kind: "dns", completed_at: 1, addresses: ["8.8.8.8"], overflow: false, failure: null };
  for (const mutant of oneFieldMutants(fact)) assert.throws(() => reduceFetchMachine(pending, mutant), TypeError);
});

test("metadata overflow and redirect semantics issue discard before disposition", () => {
  let machine = createFetchMachine("https://public.example.co/start", LIMITS, 0);
  machine = reduceFetchMachine(machine, { kind: "dns", completed_at: 1, addresses: ["8.8.8.8"], overflow: false, failure: null });
  machine = reduceFetchMachine(machine, { kind: "fetch", completed_at: 2, failure: null });
  const overlong = headers(); overlong.location = { value: null, overflow: true };
  machine = reduceFetchMachine(machine, { kind: "metadata", completed_at: 3, status: 302, headers: overlong, failure: null });
  assert.equal(machine.pending.kind, "discard");
  machine = reduceFetchMachine(machine, { kind: "discard", completed_at: 3 });
  assert.equal(machine.terminal.reason, "url_too_long");
});

test("deadlines include exact boundary and reject completion-clock-late facts", () => {
  let atBoundary = createFetchMachine("https://public.example.co/", LIMITS, 0);
  atBoundary = reduceFetchMachine(atBoundary, { kind: "dns", completed_at: 100, addresses: ["8.8.8.8"], overflow: false, failure: null });
  assert.equal(atBoundary.pending.kind, "fetch");
  let late = createFetchMachine("https://public.example.co/", LIMITS, 0);
  late = reduceFetchMachine(late, { kind: "dns", completed_at: 101, addresses: ["8.8.8.8"], overflow: false, failure: null });
  assert.equal(late.terminal.reason, "timeout");
});
