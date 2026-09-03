import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { dirname, isAbsolute, join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { spawnSync } from "node:child_process";

const REPO = "tyu41275/watch-dog", SHA = /^[a-f0-9]{40}$/u;
const PHASES = new Set(["merge_intent", "merged", "ref_intent", "dispatch_intent",
  "dispatch_accepted", "complete"]);
class TransitionError extends Error { constructor(code) { super(code); this.code = code; } }
const requireState = (condition, code) => { if (!condition) throw new TransitionError(code); };

export function parseTransitionArgs(argv) {
  const values = { checkOnly: false };
  for (let index = 0; index < argv.length; index += 1) {
    const item = argv[index];
    if (item === "--check-only") values.checkOnly = true;
    else if (item === "--pr" && /^\d+$/u.test(argv[index + 1] ?? ""))
      values.pr = Number(argv[++index]);
    else if (item === "--expected-head" && SHA.test(argv[index + 1] ?? ""))
      values.head = argv[++index];
    else throw new TransitionError("invalid_arguments");
  }
  requireState(Number.isSafeInteger(values.pr) && values.pr > 0 && SHA.test(values.head ?? ""),
    "invalid_arguments");
  return values;
}

function command(program, args) {
  const result = spawnSync(program, args, { encoding: "utf8", timeout: 15_000,
    maxBuffer: 2_000_000, env: { ...process.env, GH_PROMPT_DISABLED: "1" } });
  requireState(result.status === 0, `${program}_command_failed`);
  if (result.stdout.trim() === "") return null;
  try { return JSON.parse(result.stdout); } catch { throw new TransitionError("invalid_command_output"); }
}
const defaultRun = (args) => command("gh", args);
const endpoint = (path) => ["api", `repos/${REPO}/${path}`];
const api = (run, path, method, fields = []) => run([
  ...endpoint(path), ...(method === "GET" ? [] : ["--method", method]),
  ...fields.flatMap(([name, value]) => ["-f", `${name}=${value}`]),
]);
const refName = (value) => typeof value === "string" && value.length <= 240 &&
  /^(?!\/)(?!.*(?:\.\.|\/\/|\.lock(?:\/|$)))[A-Za-z0-9._/-]+$/u.test(value);

async function journalAt(options, pr, head) {
  if (options.gitDir) return join(resolve(options.gitDir), `wd10-transition-${pr}-${head}.json`);
  const value = spawnSync("git", ["rev-parse", "--git-dir"], { encoding: "utf8", timeout: 5_000 });
  requireState(value.status === 0, "git_directory_unavailable");
  const raw = value.stdout.trim();
  return join(isAbsolute(raw) ? raw : resolve(raw), `wd10-transition-${pr}-${head}.json`);
}
async function readJournal(path, pr, head) {
  try {
    const value = JSON.parse(await readFile(path, "utf8"));
    requireState(value?.version === 1 && value.pr === pr && value.head === head && SHA.test(value.base) &&
      refName(value.ref) && PHASES.has(value.phase) &&
      (value.run_id === undefined || Number.isSafeInteger(value.run_id)), "journal_invalid");
    return value;
  } catch (error) {
    if (error?.code === "ENOENT") return null;
    if (error instanceof TransitionError) throw error;
    throw new TransitionError("journal_invalid");
  }
}
async function persist(path, state) {
  await mkdir(dirname(path), { recursive: true });
  const temporary = `${path}.${process.pid}.tmp`;
  await writeFile(temporary, `${JSON.stringify(state)}\n`, { mode: 0o600 });
  await rename(temporary, path);
}

function sourceRefs(run, ref) {
  const result = api(run, `git/matching-refs/heads/${encodeURIComponent(ref)}`, "GET");
  requireState(Array.isArray(result), "source_ref_invalid");
  return result.filter((item) => item?.ref === `refs/heads/${ref}`);
}
function authenticatePr(value, pr, head) {
  requireState(value?.number === pr && value?.head?.repo?.full_name === REPO &&
    value.head.sha === head && refName(value.head.ref) && value?.base?.ref === "main" &&
    SHA.test(value.base.sha), "pull_request_mismatch");
  requireState((value.state === "open" && value.merged === false) || value.merged === true,
    "pull_request_not_transitionable");
  return value;
}
function proveAncestor(run, ancestor, descendant, code) {
  const comparison = api(run, `compare/${ancestor}...${descendant}`, "GET");
  requireState(comparison?.merge_base_commit?.sha === ancestor &&
    ["ahead", "identical"].includes(comparison.status), code);
}
function matchingRuns(run, ref, head) {
  const value = api(run, `actions/workflows/deploy.yml/runs?branch=${encodeURIComponent(ref)}&event=workflow_dispatch&per_page=100`, "GET");
  requireState(Array.isArray(value?.workflow_runs), "workflow_runs_invalid");
  const scoped = value.workflow_runs.filter((item) => item?.head_branch === ref &&
    item?.event === "workflow_dispatch");
  requireState(!scoped.some((item) => item.head_sha !== head), "workflow_run_ref_drift");
  const matches = scoped.filter((item) => item.head_sha === head);
  requireState(matches.length <= 1, "duplicate_workflow_runs");
  return matches;
}

export async function deploymentTransition(options) {
  const { pr, head, checkOnly } = options;
  const run = options.run ?? defaultRun, sleep = options.sleep ??
    ((milliseconds) => new Promise((done) => setTimeout(done, milliseconds)));
  requireState(typeof run(["api", "user"])?.login === "string", "github_auth_failed");
  const repository = api(run, "", "GET");
  requireState(repository?.full_name === REPO && repository.default_branch === "main" &&
    repository.archived === false && repository.disabled === false, "repository_mismatch");
  let main = api(run, "git/ref/heads/main", "GET")?.object?.sha;
  requireState(SHA.test(main ?? ""), "main_ref_invalid");
  const workflow = api(run, `contents/.github/workflows/deploy.yml?ref=${head}`, "GET");
  requireState(workflow?.type === "file" && SHA.test(workflow.sha ?? ""), "workflow_missing");
  let pull = authenticatePr(api(run, `pulls/${pr}`, "GET"), pr, head);
  proveAncestor(run, pull.base.sha, main, "base_not_in_main");
  if (!pull.merged) requireState(main === pull.base.sha, "main_moved");
  let refs = sourceRefs(run, pull.head.ref);
  requireState(refs.length <= 1 && (refs.length === 0 || refs[0]?.object?.sha === head),
    "source_ref_drift");
  requireState(pull.merged || refs.length === 1, "source_ref_missing");
  if (checkOnly) {
    if (pull.merged) proveAncestor(run, head, main, "head_not_in_main");
    return { repository: REPO, pr, head, base: pull.base.sha, main,
      ref: pull.head.ref, state: pull.merged ? "merged" : "open", check_only: true };
  }
  const journalPath = await journalAt(options, pr, head);
  let journal = await readJournal(journalPath, pr, head);
  if (journal !== null) requireState(journal.ref === pull.head.ref, "journal_ref_mismatch");
  let merge = "resumed", dispatch = "resumed";
  if (!pull.merged) {
    requireState(journal === null || journal.phase === "merge_intent", "journal_state_conflict");
    requireState(journal === null || journal.base === pull.base.sha, "journal_base_mismatch");
    journal = { version: 1, pr, head, base: pull.base.sha, ref: pull.head.ref, phase: "merge_intent" };
    await persist(journalPath, journal);
    const merged = api(run, `pulls/${pr}/merge`, "PUT",
      [["sha", head], ["merge_method", "merge"]]);
    requireState(merged?.merged === true, "merge_not_accepted");
    merge = "performed";
  }
  pull = authenticatePr(api(run, `pulls/${pr}`, "GET"), pr, head);
  requireState(pull.merged === true, "merge_not_authenticated");
  main = api(run, "git/ref/heads/main", "GET")?.object?.sha;
  requireState(SHA.test(main ?? ""), "main_ref_invalid");
  const acceptedBase = journal?.base ?? pull.base.sha;
  proveAncestor(run, acceptedBase, main, "base_not_in_main");
  proveAncestor(run, head, main, "head_not_in_main");
  if (journal === null || journal.phase === "merge_intent") {
    journal = { version: 1, pr, head, base: acceptedBase, ref: pull.head.ref, phase: "merged" };
    await persist(journalPath, journal);
  }
  refs = sourceRefs(run, pull.head.ref);
  requireState(refs.length <= 1 && (refs.length === 0 || refs[0]?.object?.sha === head),
    "source_ref_drift");
  if (refs.length === 0) {
    if (["merged", "ref_intent"].includes(journal.phase)) journal.phase = "ref_intent";
    await persist(journalPath, journal);
    api(run, "git/refs", "POST", [["ref", `refs/heads/${pull.head.ref}`], ["sha", head]]);
  }
  refs = sourceRefs(run, pull.head.ref);
  requireState(refs.length === 1 && refs[0]?.object?.sha === head, "source_ref_not_retained");
  let matches = matchingRuns(run, pull.head.ref, head);
  if (matches.length === 0 && ["dispatch_intent", "dispatch_accepted", "complete"].includes(journal.phase))
    throw new TransitionError("DISPATCH_OUTCOME_UNKNOWN");
  if (matches.length === 0) {
    journal.phase = "dispatch_intent"; await persist(journalPath, journal);
    api(run, "actions/workflows/deploy.yml/dispatches", "POST",
      [["ref", pull.head.ref], ["inputs[expected_sha]", head]]);
    dispatch = "performed"; journal.phase = "dispatch_accepted"; await persist(journalPath, journal);
    for (let attempt = 0; attempt < 8 && matches.length === 0; attempt += 1) {
      await sleep(2_000); matches = matchingRuns(run, pull.head.ref, head);
    }
    requireState(matches.length === 1, "DISPATCH_OUTCOME_UNKNOWN");
  }
  const runId = matches[0]?.id;
  requireState(Number.isSafeInteger(runId), "workflow_run_invalid");
  journal = { ...journal, phase: "complete", run_id: runId }; await persist(journalPath, journal);
  return { repository: REPO, pr, head, base: acceptedBase, main, ref: pull.head.ref,
    state: "dispatched", merge, dispatch, ancestry: "proved", run_id: runId };
}

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  Promise.resolve().then(() => deploymentTransition(parseTransitionArgs(process.argv.slice(2)))).then(
    (result) => console.log(JSON.stringify(result)),
    (error) => { console.error(`DEPLOYMENT_TRANSITION_FAIL:${error instanceof TransitionError ? error.code : "unexpected"}`); process.exitCode = 1; });
}
