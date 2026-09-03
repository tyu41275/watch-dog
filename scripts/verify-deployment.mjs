import { writeFile } from "node:fs/promises";

class GateFailure extends Error {
  constructor(code) { super(code); this.code = code; }
}

function check(condition, code) {
  if (!condition) throw new GateFailure(code);
}

const required = (name) => {
  const value = process.env[name];
  check(typeof value === "string" && value.length > 0, `missing_${name.toLowerCase()}`);
  return value;
};

const base = new URL(required("DEPLOYED_URL"));
const expectedRevision = required("EXPECTED_SHA");
const username = required("WATCH_DOG_JUDGE_USERNAME");
const password = required("WATCH_DOG_JUDGE_PASSWORD");
const evidencePath = required("EVIDENCE_PATH");
const deploymentId = required("DEPLOYMENT_ID_REDACTED");
check(base.protocol === "https:" && base.pathname === "/" && base.search === "" &&
  base.hash === "" && base.hostname.endsWith(".workers.dev"), "invalid_deployment_surface");
check(/^[a-f0-9]{40}$/u.test(expectedRevision), "invalid_expected_revision");
check(process.env.WATCH_DOG_PROVIDER_CONSENT === "true", "provider_consent_missing");
check(/^[A-Za-z0-9-]{4,12}…[A-Za-z0-9-]{2,8}$/u.test(deploymentId),
  "deployment_id_not_redacted");

const endpoint = (path) => new URL(path, base);
const request = async (path, init = {}) => {
  try {
    return await fetch(endpoint(path), {
      redirect: "manual",
      signal: AbortSignal.timeout(30_000),
      ...init,
    });
  } catch {
    throw new GateFailure("https_request_failed");
  }
};

const json = async (response, code) => {
  let text;
  try { text = await response.text(); } catch { throw new GateFailure(`${code}_body_failed`); }
  check(text.length <= 1_000_000, `${code}_body_unbounded`);
  try { return JSON.parse(text); } catch { throw new GateFailure(`${code}_body_malformed`); }
};

const exact = (value, keys) => typeof value === "object" && value !== null &&
  !Array.isArray(value) && Object.keys(value).sort().join() === [...keys].sort().join();

const post = (path, body, session, csrf) => request(path, {
  method: "POST",
  headers: {
    "content-type": "application/json",
    origin: base.origin,
    ...(session === undefined ? {} : { cookie: session.cookie }),
    ...(csrf === undefined ? {} : { "x-watchdog-csrf": csrf }),
  },
  body: JSON.stringify(body),
});

function parseCookie(header, { allowEmpty = false, maxAge = "900" } = {}) {
  check(typeof header === "string", "login_cookie_missing");
  const parts = header.split(";").map((part) => part.trim());
  const first = parts.shift();
  check(typeof first === "string" && first.startsWith("__Host-watchdog_session=") &&
    (allowEmpty || first.length > "__Host-watchdog_session=".length), "login_cookie_name");
  const attributes = new Map(parts.map((part) => {
    const separator = part.indexOf("=");
    return separator < 0
      ? [part.toLowerCase(), true]
      : [part.slice(0, separator).toLowerCase(), part.slice(separator + 1)];
  }));
  check(attributes.get("secure") === true, "login_cookie_secure");
  check(attributes.get("httponly") === true, "login_cookie_httponly");
  check(String(attributes.get("samesite")).toLowerCase() === "strict",
    "login_cookie_samesite");
  check(attributes.get("path") === "/", "login_cookie_path");
  check(attributes.get("max-age") === maxAge, "login_cookie_ttl");
  check(!attributes.has("domain"), "login_cookie_host_scope");
  return { cookie: first, attributes };
}

async function login(suppliedUsername, suppliedPassword) {
  const response = await post("/api/login", {
    username: suppliedUsername,
    password: suppliedPassword,
  });
  const body = await json(response, "login");
  return { response, body };
}

async function correctLogin() {
  const { response, body } = await login(username, password);
  check(response.status === 200 && exact(body,
    ["authenticated", "csrf_token", "expires_at"]) && body.authenticated === true,
  "correct_login_rejected");
  check(typeof body.csrf_token === "string" && /^[A-Za-z0-9_-]{32}$/u.test(body.csrf_token),
    "login_csrf_shape");
  const remaining = (Date.parse(body.expires_at) - Date.now()) / 1_000;
  check(Number.isFinite(remaining) && remaining > 880 && remaining <= 900,
    "login_session_ttl");
  return { ...parseCookie(response.headers.get("set-cookie")), csrf: body.csrf_token };
}

async function sessionStatus(session, expectedStatus) {
  const response = await request("/api/session", {
    headers: session === undefined ? {} : { cookie: session.cookie },
  });
  const body = await json(response, "session");
  check(response.status === expectedStatus, "session_status");
  if (expectedStatus === 200) {
    check(exact(body, ["authenticated", "csrf_token", "expires_at"]) &&
      body.authenticated === true && body.csrf_token === session.csrf, "session_body");
  } else {
    check(exact(body, ["error"]) && body.error === "unauthorized", "session_denial_body");
  }
}

async function scanUrl(session, target) {
  const response = await post("/api/scans/paste", { mode: "url", url: target },
    session, session.csrf);
  const body = await json(response, "scan");
  check(response.status === 201 && typeof body === "object" && body !== null &&
    Array.isArray(body.scan_ids) && body.scan_ids.length >= 1 &&
    body.scan_ids.every((id) => typeof id === "string" && /^[a-f0-9]{32}$/u.test(id)),
  "scan_receipt");
  return body;
}

async function result(session, scanId, expectedStatus = 200) {
  const response = await request(`/api/results/${scanId}`, {
    headers: { cookie: session.cookie },
  });
  const body = await json(response, "result");
  check(response.status === expectedStatus, "result_status");
  return body;
}

async function refusal(session, target, failureClass) {
  const receipt = await scanUrl(session, target);
  check(receipt.accepted_targets === 0 &&
    ["unsafe_address", "mixed_address"].includes(receipt.unscannable_reason),
  `network_${failureClass}_not_refused`);
  const stored = await result(session, receipt.scan_ids[0]);
  check(stored?.status === "ok" && stored?.result?.analysis_state === "unscannable",
    `network_${failureClass}_result`);
  return receipt.unscannable_reason;
}

async function logout(session) {
  const response = await post("/api/logout", {}, session, session.csrf);
  const body = await json(response, "logout");
  check(response.status === 200 && exact(body, ["authenticated"]) &&
    body.authenticated === false, "logout_rejected");
  const expired = parseCookie(response.headers.get("set-cookie"),
    { allowEmpty: true, maxAge: "0" });
  check(expired.cookie === "__Host-watchdog_session=", "logout_cookie_value_not_cleared");
  check(expired.attributes.get("max-age") === "0", "logout_cookie_not_expired");
}

async function main() {
  const revisionResponse = await request("/api/revision");
  const revisionBody = await json(revisionResponse, "revision");
  check(revisionResponse.status === 200 && exact(revisionBody, ["revision"]) &&
    revisionBody.revision === expectedRevision, "deployed_revision_mismatch");

  const health = await request("/api/health");
  check(health.status === 200 && (await json(health, "health"))?.status === "ok",
    "health_failed");
  for (const [path, marker] of [["/", "<h1>Watch Dog</h1>"],
    ["/reference", "<h1>Watch Dog-owned reference page</h1>"]]) {
    const response = await request(path);
    let body = "";
    try { body = await response.text(); } catch { throw new GateFailure("ui_body_failed"); }
    check(response.status === 200 && body.length <= 250_000 && body.includes(marker),
      path === "/" ? "root_ui_failed" : "reference_ui_failed");
  }

  const wrong = await login(username, `${password}\u0000`);
  check(wrong.response.status === 401 && exact(wrong.body, ["error"]) &&
    wrong.body.error === "invalid_credentials" &&
    wrong.response.headers.get("set-cookie") === null, "wrong_login_not_generic");

  const first = await correctLogin();
  await sessionStatus(first, 200);
  const missingCsrf = await post("/api/scans/paste", { mode: "html", html: "", base_url: base.origin },
    first);
  check(missingCsrf.status === 401 && (await json(missingCsrf, "csrf"))?.error === "unauthorized",
    "csrf_denial_failed");

  const publicControl = new URL(`https://${["example", "com"].join(".")}/`).href;
  const publicReceipt = await scanUrl(first, publicControl);
  check(publicReceipt.accepted_targets > 0 && publicReceipt.unscannable_reason === null &&
    Array.isArray(publicReceipt.fetch_evidence?.validated_hops) &&
    publicReceipt.fetch_evidence.validated_hops.length > 0, "public_fetch_failed");
  const owned = await result(first, publicReceipt.scan_ids[0]);
  const observation = owned?.result?.provider_observations?.[0];
  check(owned?.status === "ok" && observation?.provider === "google_safe_browsing" &&
    observation?.source === "live" && ["match", "no_match"].includes(observation?.state) &&
    observation?.error === null, "live_provider_failed");

  const second = await correctLogin();
  const cross = await result(second, publicReceipt.scan_ids[0], 403);
  check(exact(cross, ["error"]) && cross.error === "unauthorized", "cross_session_denial_failed");

  const loopback = new URL(`http://${[127, 0, 0, 1].join(".")}/`).href;
  const privateAddress = new URL(`http://${[10, 0, 0, 1].join(".")}/`).href;
  const rebindingStyle = new URL(`https://${["localtest", "me"].join(".")}/`).href;
  const redirect = new URL("/redirect-to", `https://${["httpbingo", "org"].join(".")}`);
  redirect.searchParams.set("url", loopback);
  const refusals = {
    loopback: await refusal(first, loopback, "loopback"),
    private: await refusal(first, privateAddress, "private"),
    rebinding_style: await refusal(first, rebindingStyle, "rebinding"),
    redirect_to_disallowed: await refusal(first, redirect.href, "redirect"),
  };

  const badLogout = await post("/api/logout", {}, first, "invalid");
  check(badLogout.status === 401 && (await json(badLogout, "logout_csrf"))?.error ===
    "unauthorized", "logout_csrf_denial_failed");
  await sessionStatus(first, 200);
  await logout(first);
  await sessionStatus(undefined, 401);
  await logout(second);

  const evidence = {
    schema_version: 1,
    generated_at: new Date().toISOString(),
    deployment: {
      url: base.href,
      deployment_id: deploymentId,
      revision: expectedRevision,
      https: true,
      surface: "workers.dev",
    },
    authentication: {
      wrong_login: "generic_denial",
      correct_login: "accepted",
      csrf_denial: "passed",
      csrf_acceptance: "passed",
      logout_expiry: "passed",
      session_status: "passed",
      same_session_ownership: "passed",
      cross_session_denial: "passed",
    },
    cookie: {
      name: "__Host-watchdog_session",
      secure: true,
      http_only: true,
      same_site: "Strict",
      path: "/",
      max_age_seconds: 900,
      value_preserved: false,
    },
    provider: {
      provider: "google_safe_browsing",
      source: "live",
      consented: true,
      use: "non-commercial",
      state: observation.state,
      raw_payload_preserved: false,
      queried_target_preserved: false,
    },
    network: {
      public_fetch: "passed",
      refusal_reasons: refusals,
      probe_targets_preserved: false,
    },
    ui: { root: "passed", reference: "passed" },
    secrets_or_credentials_preserved: false,
  };
  await writeFile(evidencePath, `${JSON.stringify(evidence, null, 2)}\n`, { mode: 0o600 });
  console.log("LIVE_VERIFICATION_PASS");
}

main().catch((error) => {
  const code = error instanceof GateFailure ? error.code : "unexpected_verifier_failure";
  console.error(`LIVE_VERIFICATION_FAIL:${code}`);
  process.exitCode = 1;
});
