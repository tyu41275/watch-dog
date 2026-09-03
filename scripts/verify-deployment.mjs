import { writeFile } from "node:fs/promises";
import { PUBLIC_CONTROL } from "./verify-public-control.mjs";

class GateFailure extends Error { constructor(code) { super(code); this.code = code; } }
const check = (condition, code) => { if (!condition) throw new GateFailure(code); };
const required = (name) => { const value = process.env[name];
  check(typeof value === "string" && value.length > 0, `missing_${name.toLowerCase()}`); return value; };
let base, revision, username, password, evidencePath, deploymentId;

const request = async (path, init = {}) => { try { return await fetch(new URL(path, base), {
  redirect: "manual", signal: AbortSignal.timeout(30_000), ...init,
}); } catch { throw new GateFailure("https_request_failed"); } };
const json = async (response, code) => { let text; try { text = await response.text(); }
  catch { throw new GateFailure(`${code}_body_failed`); }
  check(text.length <= 1_000_000, `${code}_body_unbounded`);
  try { return JSON.parse(text); } catch { throw new GateFailure(`${code}_body_malformed`); } };
const exact = (value, keys) => typeof value === "object" && value !== null &&
  !Array.isArray(value) && Object.keys(value).sort().join() === [...keys].sort().join();
const post = (path, body, session, csrf) => request(path, { method: "POST", headers: {
  "content-type": "application/json", origin: base.origin,
  ...(session ? { cookie: session.cookie } : {}),
  ...(csrf ? { "x-watchdog-csrf": csrf } : {}),
}, body: JSON.stringify(body) });

function cookie(header, { empty = false, age = "900" } = {}) {
  check(typeof header === "string", "session_cookie_missing");
  const parts = header.split(";").map((part) => part.trim()), first = parts.shift();
  check(first?.startsWith("__Host-watchdog_session=") &&
    (empty || first.length > "__Host-watchdog_session=".length), "session_cookie_name");
  const attributes = new Map(parts.map((part) => { const at = part.indexOf("=");
    return at < 0 ? [part.toLowerCase(), true] :
      [part.slice(0, at).toLowerCase(), part.slice(at + 1)]; }));
  check(attributes.get("secure") === true && attributes.get("httponly") === true &&
    String(attributes.get("samesite")).toLowerCase() === "strict" &&
    attributes.get("path") === "/" && attributes.get("max-age") === age &&
    !attributes.has("domain"), "session_cookie_attributes");
  return { cookie: first, attributes };
}
async function login(user, pass) {
  const response = await post("/api/login", { username: user, password: pass });
  return { response, body: await json(response, "login") };
}
async function correctLogin() {
  const { response, body } = await login(username, password);
  check(response.status === 200 && exact(body, ["authenticated", "csrf_token", "expires_at"]) &&
    body.authenticated === true && /^[A-Za-z0-9_-]{32}$/u.test(body.csrf_token), "login_failed");
  const ttl = (Date.parse(body.expires_at) - Date.now()) / 1_000;
  check(Number.isFinite(ttl) && ttl > 880 && ttl <= 900, "session_ttl");
  return { ...cookie(response.headers.get("set-cookie")), csrf: body.csrf_token };
}
async function sessionStatus(session, status) {
  const response = await request("/api/session", { headers: session ? { cookie: session.cookie } : {} });
  const body = await json(response, "session"); check(response.status === status, "session_status");
  check(status === 200 ? exact(body, ["authenticated", "csrf_token", "expires_at"]) &&
    body.authenticated === true && body.csrf_token === session.csrf :
    exact(body, ["error"]) && body.error === "unauthorized", "session_body");
}
async function scan(session, target) {
  const response = await post("/api/scans/paste", { mode: "url", url: target }, session, session.csrf);
  const body = await json(response, "scan");
  check(response.status === 201 && Array.isArray(body?.scan_ids) &&
    body.scan_ids.every((id) => /^[a-f0-9]{32}$/u.test(id)), "scan_receipt"); return body;
}
async function getResult(session, id, status = 200) {
  const response = await request(`/api/results/${id}`, { headers: { cookie: session.cookie } });
  const body = await json(response, "result"); check(response.status === status, "result_status"); return body;
}
async function refusal(session, target, name) {
  const receipt = await scan(session, target);
  check(receipt.accepted_targets === 0 && ["unsafe_address", "mixed_address"].includes(
    receipt.unscannable_reason), `network_${name}_not_refused`);
  const stored = await getResult(session, receipt.scan_ids[0]);
  check(stored?.status === "ok" && stored?.result?.analysis_state === "unscannable",
    `network_${name}_result`); return receipt.unscannable_reason;
}
async function logout(session) {
  const response = await post("/api/logout", {}, session, session.csrf), body = await json(response, "logout");
  check(response.status === 200 && exact(body, ["authenticated"]) && body.authenticated === false,
    "logout_failed");
  const expired = cookie(response.headers.get("set-cookie"), { empty: true, age: "0" });
  check(expired.cookie === "__Host-watchdog_session=", "logout_cookie_not_cleared");
}

async function main() {
  base = new URL(required("DEPLOYED_URL")); revision = required("EXPECTED_SHA");
  username = required("WATCH_DOG_JUDGE_USERNAME").trim(); password = required("WATCH_DOG_JUDGE_PASSWORD");
  check(username.length > 0, "empty_watch_dog_judge_username");
  evidencePath = required("EVIDENCE_PATH"); deploymentId = required("DEPLOYMENT_ID_REDACTED");
  check(base.protocol === "https:" && base.pathname === "/" && base.search === "" &&
    base.hash === "" && base.hostname.endsWith(".workers.dev"), "invalid_deployment_surface");
  check(/^[a-f0-9]{40}$/u.test(revision), "invalid_expected_revision");
  check(process.env.WATCH_DOG_PROVIDER_CONSENT === "true", "provider_consent_missing");
  check(/^[A-Za-z0-9-]{4,12}…[A-Za-z0-9-]{2,8}$/u.test(deploymentId),
    "deployment_id_not_redacted");
  let response = await request("/api/revision"), body = await json(response, "revision");
  check(response.status === 200 && exact(body, ["revision"]) && body.revision === revision,
    "deployed_revision_mismatch");
  response = await request("/api/health");
  check(response.status === 200 && (await json(response, "health"))?.status === "ok", "health_failed");
  for (const [path, marker] of [["/", "<h1>Watch Dog</h1>"],
    ["/reference", "<h1>Watch Dog-owned reference page</h1>"]]) {
    response = await request(path); let text = ""; try { text = await response.text(); }
    catch { throw new GateFailure("ui_body_failed"); }
    check(response.status === 200 && text.length <= 250_000 && text.includes(marker), "ui_failed");
  }
  const wrong = await login(username, `${password}\u0000`);
  check(wrong.response.status === 401 && exact(wrong.body, ["error"]) &&
    wrong.body.error === "invalid_credentials" && !wrong.response.headers.has("set-cookie"),
  "wrong_login_not_generic");
  const first = await correctLogin(); await sessionStatus(first, 200);
  response = await post("/api/scans/paste", { mode: "html", html: "", base_url: base.origin }, first);
  check(response.status === 401 && (await json(response, "csrf"))?.error === "unauthorized",
    "missing_csrf_accepted");
  const receipt = await scan(first, PUBLIC_CONTROL.url);
  const actualTargets = receipt.targets?.map(({ canonical_url }) => canonical_url).sort();
  check(receipt.accepted_targets === 2 && receipt.occurrence_count?.kind === "exact" &&
    receipt.occurrence_count.count === 2 &&
    receipt.targets?.every(({ occurrences }) => occurrences?.length === 1) &&
    receipt.rejected_candidates === 0 &&
    receipt.unscannable_reason === null && receipt.scan_ids.length === 2 &&
    JSON.stringify(actualTargets) === JSON.stringify([...PUBLIC_CONTROL.targets].sort()) &&
    receipt.fetch_evidence?.requested_url === PUBLIC_CONTROL.url &&
    receipt.fetch_evidence?.final_url === PUBLIC_CONTROL.url &&
    receipt.fetch_evidence?.redirect_chain?.length === 0 &&
    receipt.fetch_evidence?.validated_hops?.length === 1 &&
    receipt.fetch_evidence.validated_hops[0]?.hostname === "httpbingo.org",
  "public_control_failed");
  const observations = [], storedTargets = [];
  for (const id of receipt.scan_ids) {
    const stored = await getResult(first, id), observation = stored?.result?.provider_observations?.[0];
    check(stored?.status === "ok" && observation?.provider === "google_safe_browsing" &&
      observation.source === "live" && ["match", "no_match"].includes(observation.state) &&
      observation.error === null && observation.queried_target === stored.result.canonical_target,
    "live_provider_failed"); observations.push(observation.state);
    storedTargets.push(stored.result.canonical_target);
  }
  check(JSON.stringify(storedTargets.sort()) === JSON.stringify([...PUBLIC_CONTROL.targets].sort()),
    "stored_control_targets_mismatch");
  const second = await correctLogin();
  for (const id of receipt.scan_ids) {
    const denied = await getResult(second, id, 403);
    check(exact(denied, ["error"]) && denied.error === "unauthorized", "cross_session_denial_failed");
  }
  const loopback = `http://${[127, 0, 0, 1].join(".")}/`;
  const redirect = new URL("/redirect-to", `https://${["httpbingo", "org"].join(".")}`);
  redirect.searchParams.set("url", loopback);
  const refusals = {
    loopback: await refusal(first, loopback, "loopback"),
    private: await refusal(first, `http://${[10, 0, 0, 1].join(".")}/`, "private"),
    rebinding_style: await refusal(first, `https://${["localtest", "me"].join(".")}/`, "rebinding"),
    redirect_to_disallowed: await refusal(first, redirect.href, "redirect"),
  };
  response = await post("/api/logout", {}, first, "invalid");
  check(response.status === 401 && (await json(response, "logout_csrf"))?.error === "unauthorized",
    "logout_csrf_denial_failed");
  await sessionStatus(first, 200); await logout(first); await sessionStatus(undefined, 401);
  await logout(second); await sessionStatus(undefined, 401);
  const evidence = { schema_version: 1, generated_at: new Date().toISOString(),
    deployment: { url: base.href, deployment_id: deploymentId, revision, https: true,
      surface: "workers.dev" },
    authentication: { wrong_login: "generic_denial", correct_login: "accepted",
      csrf_denial: "passed", csrf_acceptance: "passed", logout_expiry: "passed",
      session_status: "passed", same_session_ownership: "passed", cross_session_denial: "passed" },
    cookie: { name: "__Host-watchdog_session", secure: true, http_only: true,
      same_site: "Strict", path: "/", max_age_seconds: 900, value_preserved: false },
    provider: { provider: "google_safe_browsing", source: "live", consented: true,
      use: "non-commercial", states: observations, raw_payload_preserved: false,
      queried_targets_preserved: false },
    network: { public_control: PUBLIC_CONTROL.id, accepted_targets: 2,
      refusal_reasons: refusals, probe_targets_preserved: false },
    ui: { root: "passed", reference: "passed" }, secrets_or_credentials_preserved: false };
  await writeFile(evidencePath, `${JSON.stringify(evidence, null, 2)}\n`, { mode: 0o600 });
  console.log("LIVE_VERIFICATION_PASS");
}
main().catch((error) => { console.error(`LIVE_VERIFICATION_FAIL:${error instanceof GateFailure ?
  error.code : "unexpected_verifier_failure"}`); process.exitCode = 1; });
