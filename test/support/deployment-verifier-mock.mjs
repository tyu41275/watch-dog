const json = (body, init = {}) => Response.json(body, init);
let loginCount = 0;
let scanCount = 0;
const publicId = "1".repeat(32);

globalThis.fetch = async (input, init = {}) => {
  const url = new URL(input);
  const headers = new Headers(init.headers);
  if (url.pathname === "/api/revision") {
    return json({ revision: process.env.EXPECTED_SHA });
  }
  if (url.pathname === "/api/health") return json({ status: "ok", service: "watch-dog" });
  if (url.pathname === "/") return new Response("<h1>Watch Dog</h1>");
  if (url.pathname === "/reference") {
    return new Response("<h1>Watch Dog-owned reference page</h1>");
  }
  if (url.pathname === "/api/login") {
    const body = JSON.parse(init.body);
    if (body.username !== process.env.WATCH_DOG_JUDGE_USERNAME ||
      body.password !== process.env.WATCH_DOG_JUDGE_PASSWORD) {
      return json({ error: "invalid_credentials" }, { status: 401 });
    }
    loginCount += 1;
    const csrf = String(loginCount).repeat(32);
    return json({ authenticated: true, csrf_token: csrf,
      expires_at: new Date(Date.now() + 900_000).toISOString() }, {
      headers: { "set-cookie": `__Host-watchdog_session=token-${loginCount}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=900` },
    });
  }
  if (url.pathname === "/api/session") {
    return headers.has("cookie")
      ? json({ authenticated: true, csrf_token: "1".repeat(32),
          expires_at: new Date(Date.now() + 900_000).toISOString() })
      : json({ error: "unauthorized" }, { status: 401 });
  }
  if (url.pathname === "/api/scans/paste") {
    if (!headers.has("x-watchdog-csrf")) {
      return json({ error: "unauthorized" }, { status: 401 });
    }
    scanCount += 1;
    const id = scanCount === 1 ? publicId : String(scanCount).repeat(32);
    const accepted = scanCount === 1;
    return json({
      scan_ids: [id],
      accepted_targets: accepted ? 1 : 0,
      unscannable_reason: accepted ? null : "unsafe_address",
      fetch_evidence: { validated_hops: accepted ? [{ hostname: "redacted", address_count: 1 }] : [] },
    }, { status: 201 });
  }
  const result = /^\/api\/results\/([a-f0-9]{32})$/u.exec(url.pathname);
  if (result !== null) {
    if (result[1] === publicId && headers.get("cookie") === "__Host-watchdog_session=token-2") {
      return json({ error: "unauthorized" }, { status: 403 });
    }
    return result[1] === publicId
      ? json({ status: "ok", result: { analysis_state: "unknown", provider_observations: [{
          provider: "google_safe_browsing", source: "live", state: "no_match", error: null,
        }] } })
      : json({ status: "ok", result: { analysis_state: "unscannable" } });
  }
  if (url.pathname === "/api/logout") {
    if (headers.get("x-watchdog-csrf") === "invalid") {
      return json({ error: "unauthorized" }, { status: 401 });
    }
    return json({ authenticated: false }, {
      headers: { "set-cookie": "__Host-watchdog_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0" },
    });
  }
  return json({ error: "not_found" }, { status: 404 });
};
