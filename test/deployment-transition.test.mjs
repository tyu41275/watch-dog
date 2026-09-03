import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { deploymentTransition, parseTransitionArgs } from "../scripts/deployment-transition.mjs";

const head = "a".repeat(40), base = "2".repeat(40), mergedMain = "3".repeat(40);
function github(options = {}) {
  const state = { merged: options.merged ?? false, main: options.main ??
    (options.merged ? mergedMain : base), ref: options.ref ?? true,
    runs: options.runs ? structuredClone(options.runs) : [], mergeCalls: 0,
    dispatchCalls: 0, refCreates: 0 };
  const run = (args) => {
    if (args[0] === "auth") return null;
    const path = args[1].replace("repos/tyu41275/watch-dog/", "");
    const method = args.includes("--method") ? args[args.indexOf("--method") + 1] : "GET";
    if (path === "") return { full_name: "tyu41275/watch-dog", default_branch: "main",
      archived: false, disabled: false };
    if (path === "git/ref/heads/main") return { object: { sha: state.main } };
    if (path.startsWith("contents/.github/workflows/deploy.yml"))
      return { type: "file", sha: "4".repeat(40) };
    if (path === "pulls/51") return { number: 51, state: state.merged || options.closed ? "closed" : "open",
      merged: state.merged, head: { sha: options.wrongHead ? "9".repeat(40) : head,
        ref: "agent/replacement", repo: { full_name: options.fork ? "other/fork" : "tyu41275/watch-dog" } },
      base: { ref: "main", sha: base } };
    if (path.startsWith("compare/")) {
      const ancestor = path.slice(8).split("...")[0];
      const valid = ancestor === base || (ancestor === head && state.merged && !options.badAncestry);
      return { status: valid ? "ahead" : "diverged",
        merge_base_commit: { sha: valid ? ancestor : "8".repeat(40) } };
    }
    if (path.startsWith("git/matching-refs/heads/")) return state.ref ?
      [{ ref: "refs/heads/agent/replacement", object: { sha: options.driftRef ?
        "7".repeat(40) : head } }] : [];
    if (path === "pulls/51/merge" && method === "PUT") {
      state.mergeCalls += 1; state.merged = true; state.main = mergedMain;
      return { merged: true };
    }
    if (path === "git/refs" && method === "POST") {
      state.refCreates += 1; state.ref = true; return { ref: "refs/heads/agent/replacement" };
    }
    if (path.startsWith("actions/workflows/deploy.yml/runs"))
      return { workflow_runs: state.runs };
    if (path === "actions/workflows/deploy.yml/dispatches" && method === "POST") {
      state.dispatchCalls += 1;
      state.runs.push({ id: 7001, head_branch: "agent/replacement",
        event: "workflow_dispatch", head_sha: head }); return null;
    }
    assert.fail(`unexpected GitHub command: ${args.join(" ")}`);
  };
  return { state, run };
}

async function directory(t) {
  const value = await mkdtemp(join(tmpdir(), "wd10-transition-"));
  t.after(() => rm(value, { recursive: true, force: true })); return value;
}

test("arguments require one explicit PR and exact lowercase head", () => {
  assert.deepEqual(parseTransitionArgs(["--pr", "51", "--expected-head", head]),
    { checkOnly: false, pr: 51, head });
  assert.throws(() => parseTransitionArgs(["--pr", "51", "--expected-head", head.toUpperCase()]),
    /invalid_arguments/);
});

test("fresh and repeated transitions merge and dispatch exactly once", async (t) => {
  const gitDir = await directory(t), fake = github();
  const first = await deploymentTransition({ pr: 51, head, checkOnly: false, gitDir,
    run: fake.run, sleep: async () => {} });
  assert.deepEqual([first.merge, first.dispatch, first.run_id], ["performed", "performed", 7001]);
  const second = await deploymentTransition({ pr: 51, head, checkOnly: false, gitDir,
    run: fake.run, sleep: async () => {} });
  assert.deepEqual([second.merge, second.dispatch], ["resumed", "resumed"]);
  assert.deepEqual([fake.state.mergeCalls, fake.state.dispatchCalls], [1, 1]);
});

test("merged state restores only an absent exact ref and resumes an existing run", async (t) => {
  const gitDir = await directory(t), fake = github({ merged: true, ref: false,
    runs: [{ id: 8002, head_branch: "agent/replacement", event: "workflow_dispatch", head_sha: head }] });
  const result = await deploymentTransition({ pr: 51, head, checkOnly: false, gitDir,
    run: fake.run, sleep: async () => {} });
  assert.equal(result.run_id, 8002);
  assert.deepEqual([fake.state.mergeCalls, fake.state.refCreates, fake.state.dispatchCalls], [0, 1, 0]);
});

test("dispatch intent without an authoritative run never redispatches", async (t) => {
  const gitDir = await directory(t), fake = github({ merged: true });
  await writeFile(join(gitDir, `wd10-transition-51-${head}.json`), JSON.stringify({
    version: 1, pr: 51, head, base, ref: "agent/replacement", phase: "dispatch_intent" }));
  await assert.rejects(deploymentTransition({ pr: 51, head, checkOnly: false, gitDir,
    run: fake.run, sleep: async () => {} }), /DISPATCH_OUTCOME_UNKNOWN/);
  assert.equal(fake.state.dispatchCalls, 0);
});

test("check-only and authenticated drift failures perform no mutations", async (t) => {
  const gitDir = await directory(t), clean = github();
  const result = await deploymentTransition({ pr: 51, head, checkOnly: true, gitDir,
    run: clean.run });
  assert.equal(result.check_only, true);
  assert.deepEqual([clean.state.mergeCalls, clean.state.dispatchCalls], [0, 0]);
  for (const fake of [github({ main: "6".repeat(40) }), github({ fork: true }),
    github({ driftRef: true }), github({ wrongHead: true }), github({ closed: true }),
    github({ merged: true, badAncestry: true })]) {
    await assert.rejects(deploymentTransition({ pr: 51, head, checkOnly: true, gitDir,
      run: fake.run }));
    assert.deepEqual([fake.state.mergeCalls, fake.state.dispatchCalls], [0, 0]);
  }
});

test("duplicate or wrong-head dispatch history fails closed", async (t) => {
  const gitDir = await directory(t);
  for (const runs of [[1, 2].map((id) => ({ id, head_branch: "agent/replacement",
    event: "workflow_dispatch", head_sha: head })), [{ id: 3, head_branch: "agent/replacement",
    event: "workflow_dispatch", head_sha: "5".repeat(40) }]]) {
    const fake = github({ merged: true, runs });
    await assert.rejects(deploymentTransition({ pr: 51, head, checkOnly: false, gitDir,
      run: fake.run, sleep: async () => {} }));
    assert.equal(fake.state.dispatchCalls, 0);
  }
});
