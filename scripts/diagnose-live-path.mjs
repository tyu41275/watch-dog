const REQUIRED = [
  "DEPLOYED_URL",
  "EXPECTED_SHA",
  "WATCH_DOG_JUDGE_USERNAME",
  "WATCH_DOG_JUDGE_PASSWORD",
  "GOOGLE_SAFE_BROWSING_API_KEY",
];

const required = Object.fromEntries(REQUIRED.map((name) => {
  const value = process.env[name];
  if (typeof value !== "string" || value.length === 0) throw new Error(`missing_${name}`);
  return [name, value];
}));

const base = new URL(required.DEPLOYED_URL);
const startedAt = new Date().toISOString();
const allowedErrors = new Set([
  "invalid_credentials", "invalid_request", "not_configured", "scan_unavailable", "unauthorized",
]);
const allowedReasons = new Set([
  "dns_failure", "fetch_failed", "input_too_large", "invalid_response", "mixed_address",
  "no_candidates", "redirect_limit", "redirect_loop", "response_too_large", "timeout",
  "unsafe_address", "unsupported_encoding", "unsupported_media_type", "unsupported_scheme",
]);

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
const boundedJson = async (response) => {
  const text = await response.text();
  if (text.length > 1_000_000) return null;
  try { return JSON.parse(text); } catch { return null; }
};
const objectKeys = (value) => typeof value === "object" && value !== null && !Array.isArray(value)
  ? Object.keys(value).sort() : [];
const safeError = (body) => allowedErrors.has(body?.error) ? body.error : body?.error == null ? null : "other";
const safeReason = (body) => allowedReasons.has(body?.unscannable_reason)
  ? body.unscannable_reason : body?.unscannable_reason == null ? null : "other";
const providerStates = new Set(["match", "no_match", "error", "not_configured"]);
const providerErrors = new Set(["timeout", "quota", "unavailable", "malformed_response", "not_configured"]);
const analysisStates = new Set(["complete", "unknown", "unscannable", "provider_error", "stale", "conflicting"]);

const evidence = {
  schema_version: 1,
  started_at: startedAt,
  expected_revision: required.EXPECTED_SHA,
  deployed_origin: base.origin,
  revision: null,
  health: null,
  login: null,
  html_scan: null,
  url_scans: null,
  logout: null,
  secret_values_preserved: false,
  cookie_value_preserved: false,
  csrf_value_preserved: false,
  scan_ids_preserved: false,
  target_values_preserved: false,
  provider_payload_preserved: false,
  direct_provider_shape: null,
};

const summarizeScan = async (response) => {
  const body = await boundedJson(response);
  return { body, summary: {
    status: response.status,
    keys: objectKeys(body),
    error: safeError(body),
    mode: ["paste_html", "paste_url"].includes(body?.mode) ? body.mode : null,
    accepted_targets: Number.isSafeInteger(body?.accepted_targets) ? body.accepted_targets : null,
    rejected_candidates: Number.isSafeInteger(body?.rejected_candidates) ? body.rejected_candidates : null,
    scan_id_count: Array.isArray(body?.scan_ids) ? body.scan_ids.length : null,
    unscannable_reason: safeReason(body),
    fetch_evidence_present: body?.fetch_evidence != null,
  } };
};

const summarizeResults = async (body, session) => {
  if (!Array.isArray(body?.scan_ids)) return [];
  return Promise.all(body.scan_ids.map(async (id) => {
    if (typeof id !== "string" || !/^[a-f0-9]{32}$/u.test(id)) return { id_shape_valid: false };
    const response = await request(`/api/results/${id}`, { headers: { cookie: session } });
    const stored = await boundedJson(response);
    const result = stored?.result;
    return {
      id_shape_valid: true,
      status: response.status,
      envelope_status: stored?.status === "ok" ? "ok" : safeError(stored),
      analysis_state: analysisStates.has(result?.analysis_state) ? result.analysis_state : null,
      observations: Array.isArray(result?.provider_observations)
        ? result.provider_observations.map((observation) => ({
          provider: observation?.provider === "google_safe_browsing" ? observation.provider : null,
          source: ["live", "fixture"].includes(observation?.source) ? observation.source : null,
          state: providerStates.has(observation?.state) ? observation.state : null,
          error: providerErrors.has(observation?.error) ? observation.error
            : observation?.error == null ? null : "other",
          freshness: ["fresh", "stale", "unknown"].includes(observation?.freshness)
            ? observation.freshness : null,
        })) : [],
    };
  }));
};

try {
  let response = await request("/api/revision");
  let body = await boundedJson(response);
  evidence.revision = {
    status: response.status,
    exact: response.status === 200 && body?.revision === required.EXPECTED_SHA,
  };

  response = await request("/api/health");
  body = await boundedJson(response);
  evidence.health = { status: response.status, ok: response.status === 200 && body?.status === "ok" };

  const providerUrl = new URL("https://safebrowsing.googleapis.com/v5/urls:search");
  providerUrl.searchParams.set("alt", "json");
  providerUrl.searchParams.append("urls", "https://httpbin.org/links/3/1");
  response = await fetch(providerUrl, {
    method: "GET",
    headers: { accept: "application/json", "x-goog-api-key": required.GOOGLE_SAFE_BROWSING_API_KEY },
    redirect: "manual",
    signal: AbortSignal.timeout(10_000),
  });
  const providerContentType = response.headers.get("content-type");
  const providerDeclaredLength = response.headers.get("content-length");
  const providerText = await response.text();
  let providerBody = null;
  try { providerBody = providerText.length <= 64_000 ? JSON.parse(providerText) : null; }
  catch { /* shape only */ }
  evidence.direct_provider_shape = {
    status: response.status,
    content_type_json: providerContentType?.split(";", 1)[0]?.trim().toLowerCase() === "application/json",
    declared_length_present: providerDeclaredLength !== null,
    declared_length_valid: providerDeclaredLength === null ||
      (Number.isSafeInteger(Number(providerDeclaredLength)) && Number(providerDeclaredLength) >= 0 &&
        Number(providerDeclaredLength) <= 64_000),
    body_within_limit: providerText.length <= 64_000,
    json_object: typeof providerBody === "object" && providerBody !== null && !Array.isArray(providerBody),
    keys: objectKeys(providerBody),
    threats_is_array: Array.isArray(providerBody?.threats),
    threat_count: Array.isArray(providerBody?.threats) ? providerBody.threats.length : null,
    cache_duration_present: Object.hasOwn(providerBody ?? {}, "cacheDuration"),
    cache_duration_is_string: typeof providerBody?.cacheDuration === "string",
    cache_duration_format_valid: typeof providerBody?.cacheDuration === "string" &&
      /^(0|[1-9][0-9]*)(?:\.([0-9]{1,9}))?s$/u.test(providerBody.cacheDuration),
  };

  response = await post("/api/login", {
    username: required.WATCH_DOG_JUDGE_USERNAME,
    password: required.WATCH_DOG_JUDGE_PASSWORD,
  });
  body = await boundedJson(response);
  const setCookie = response.headers.get("set-cookie");
  const csrf = typeof body?.csrf_token === "string" ? body.csrf_token : null;
  const session = setCookie?.split(";", 1)[0] ?? null;
  evidence.login = {
    status: response.status,
    keys: objectKeys(body),
    error: safeError(body),
    authenticated: body?.authenticated === true,
    csrf_shape_valid: csrf !== null && /^[A-Za-z0-9_-]{32}$/u.test(csrf),
    expiry_shape_valid: typeof body?.expires_at === "string" && Number.isFinite(Date.parse(body.expires_at)),
    cookie_present: typeof session === "string" && session.startsWith("__Host-watchdog_session="),
    cookie_secure: typeof setCookie === "string" && /(?:^|;)\s*Secure(?:;|$)/iu.test(setCookie),
    cookie_http_only: typeof setCookie === "string" && /(?:^|;)\s*HttpOnly(?:;|$)/iu.test(setCookie),
    cookie_same_site_strict: typeof setCookie === "string" && /(?:^|;)\s*SameSite=Strict(?:;|$)/iu.test(setCookie),
    retry_after_present: response.headers.has("retry-after"),
  };

  if (response.status === 200 && session !== null && csrf !== null) {
    const headers = { cookie: session, "x-watchdog-csrf": csrf };
    const htmlScan = await summarizeScan(await post("/api/scans/paste", {
      mode: "html",
      html: '<a href="https://example.com/">diagnostic</a>',
      base_url: base.origin,
    }, headers));
    evidence.html_scan = { ...htmlScan.summary, results: await summarizeResults(htmlScan.body, session) };
    evidence.url_scans = {};
    for (const [name, url] of [
      ["httpbingo", "https://httpbingo.org/links/3/0"],
      ["httpbin", "https://httpbin.org/links/3/0"],
      ["example", "https://example.com/"],
    ]) {
      const scan = await summarizeScan(await post("/api/scans/paste", {
        mode: "url",
        url,
      }, headers));
      evidence.url_scans[name] = {
        ...scan.summary,
        results: await summarizeResults(scan.body, session),
      };
    }
    response = await post("/api/logout", {}, headers);
    body = await boundedJson(response);
    evidence.logout = {
      status: response.status,
      keys: objectKeys(body),
      authenticated_false: body?.authenticated === false,
      cookie_cleared: response.headers.get("set-cookie")?.startsWith("__Host-watchdog_session=;") === true,
    };
  }
} catch (error) {
  evidence.transport_failure = error instanceof DOMException && error.name === "TimeoutError"
    ? "timeout" : "request_failed";
}

evidence.completed_at = new Date().toISOString();
process.stdout.write(`LIVE_PATH_DIAGNOSTIC=${JSON.stringify(evidence)}\n`);
