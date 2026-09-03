const required = (name) => {
  const value = process.env[name];
  if (typeof value !== "string" || value.length === 0) throw new Error(`missing_${name}`);
  return value;
};

const base = new URL(required("DEPLOYED_URL"));
const username = required("WATCH_DOG_JUDGE_USERNAME");
const password = required("WATCH_DOG_JUDGE_PASSWORD");
const controlUrl = "https://httpbingo.org/links/3/0";

const request = (path, init = {}) => fetch(new URL(path, base), {
  redirect: "manual",
  signal: AbortSignal.timeout(30_000),
  ...init,
});

const post = (path, body, headers = {}) => request(path, {
  method: "POST",
  headers: { "content-type": "application/json", origin: base.origin, ...headers },
  body: JSON.stringify(body),
});

const login = await post("/api/login", { username, password });
const loginBody = await login.json();
if (login.status !== 200 || loginBody?.authenticated !== true ||
  typeof loginBody.csrf_token !== "string") throw new Error("login_failed");
const session = login.headers.get("set-cookie")?.split(";", 1)[0];
if (typeof session !== "string" || !session.startsWith("__Host-watchdog_session=")) {
  throw new Error("session_missing");
}

const response = await post("/api/scans/paste", { mode: "url", url: controlUrl }, {
  cookie: session,
  "x-watchdog-csrf": loginBody.csrf_token,
});
const body = await response.json();
const summary = {
  status: response.status,
  keys: typeof body === "object" && body !== null ? Object.keys(body).sort() : [],
  mode: body?.mode ?? null,
  accepted_targets: body?.accepted_targets ?? null,
  rejected_candidates: body?.rejected_candidates ?? null,
  truncated: body?.truncated ?? null,
  unscannable_reason: body?.unscannable_reason ?? null,
  occurrence_count: body?.occurrence_count ?? null,
  scan_id_count: Array.isArray(body?.scan_ids) ? body.scan_ids.length : null,
  targets: Array.isArray(body?.targets) ? body.targets.map((target) => ({
    canonical_url: target?.canonical_url ?? null,
    occurrence_count: Array.isArray(target?.occurrences) ? target.occurrences.length : null,
  })) : null,
  fetch_evidence: body?.fetch_evidence == null ? null : {
    requested_url: body.fetch_evidence.requested_url ?? null,
    final_url: body.fetch_evidence.final_url ?? null,
    redirect_count: Array.isArray(body.fetch_evidence.redirect_chain)
      ? body.fetch_evidence.redirect_chain.length : null,
    validated_hops: Array.isArray(body.fetch_evidence.validated_hops)
      ? body.fetch_evidence.validated_hops.map((hop) => ({
          hostname: hop?.hostname ?? null,
          address_count: hop?.address_count ?? null,
        })) : null,
  },
};
console.log(`PUBLIC_CONTROL_DIAGNOSTIC:${JSON.stringify(summary)}`);

await post("/api/logout", {}, {
  cookie: session,
  "x-watchdog-csrf": loginBody.csrf_token,
});
