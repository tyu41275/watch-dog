import {
  CSRF_HEADER,
  createSession,
  expireSessionCookie,
  readAuthSecrets,
  sameOriginMutation,
  throttleFingerprint,
  verifyCredentials,
  verifySession,
} from "./auth.js";
import {
  type CoordinatorNamespace,
  SessionCoordinator,
} from "./coordinator.js";

interface AssetBinding {
  fetch(request: Request): Promise<Response>;
}

export interface Env {
  ASSETS?: AssetBinding;
  ADMIN_USERNAME?: string;
  ADMIN_PASSWORD?: string;
  SESSION_SIGNING_KEY?: string;
  GOOGLE_SAFE_BROWSING_API_KEY?: string;
  SESSION_COORDINATOR?: CoordinatorNamespace;
}

function json(body: unknown, status = 200): Response {
  return Response.json(body, {
    status,
    headers: {
      "cache-control": "no-store",
      "referrer-policy": "no-referrer",
      "x-content-type-options": "nosniff",
    },
  });
}

function coordinator(env: Env) {
  return env.SESSION_COORDINATOR?.get(env.SESSION_COORDINATOR.idFromName("global"));
}

async function bodyCredentials(request: Request) {
  const text = await request.text();
  if (text.length > 4_096) return null;
  try {
    const value = JSON.parse(text) as Record<string, unknown>;
    if (
      typeof value.username !== "string" ||
      typeof value.password !== "string" ||
      value.username.length > 256 ||
      value.password.length > 512
    ) return null;
    return { username: value.username, password: value.password };
  } catch {
    return null;
  }
}

async function login(request: Request, env: Env): Promise<Response> {
  const credentials = await bodyCredentials(request);
  const secrets = readAuthSecrets(env);
  const binding = coordinator(env);
  if (!sameOriginMutation(request) || credentials === null || secrets === null || binding === undefined) {
    return json({ error: "invalid_credentials" }, 401);
  }
  const key = await throttleFingerprint(
    request.headers.get("cf-connecting-ip") ?? "unknown",
    credentials.username,
    secrets.signingKey,
  );
  const attempt = await binding.fetch(new Request("https://coordinator/throttle/attempt", {
    method: "POST",
    body: JSON.stringify({ key }),
  }));
  const decision = await attempt.json() as { allowed?: boolean; retry_after_seconds?: number };
  if (!decision.allowed) {
    const denied = json({ error: "invalid_credentials" }, 429);
    denied.headers.set("retry-after", String(decision.retry_after_seconds ?? 600));
    return denied;
  }
  if (!await verifyCredentials(credentials.username, credentials.password, secrets)) {
    return json({ error: "invalid_credentials" }, 401);
  }
  await binding.fetch(new Request("https://coordinator/throttle/reset", {
    method: "POST",
    body: JSON.stringify({ key }),
  }));
  const session = await createSession(secrets);
  const accepted = json({
    authenticated: true,
    csrf_token: session.claims.csrf,
    expires_at: new Date(session.claims.exp * 1_000).toISOString(),
  });
  accepted.headers.set("set-cookie", session.cookie);
  return accepted;
}

async function sessionClaims(request: Request, env: Env) {
  const secrets = readAuthSecrets(env);
  return secrets === null ? null : verifySession(request.headers.get("cookie"), secrets);
}

async function sessionStatus(request: Request, env: Env): Promise<Response> {
  const claims = await sessionClaims(request, env);
  return claims === null
    ? json({ error: "unauthorized" }, 401)
    : json({ authenticated: true, expires_at: new Date(claims.exp * 1_000).toISOString() });
}

async function logout(request: Request, env: Env): Promise<Response> {
  const claims = await sessionClaims(request, env);
  if (
    claims === null ||
    !sameOriginMutation(request) ||
    request.headers.get(CSRF_HEADER) !== claims.csrf
  ) return json({ error: "unauthorized" }, 401);
  const result = json({ authenticated: false });
  result.headers.set("set-cookie", expireSessionCookie());
  return result;
}

async function getResult(request: Request, env: Env, scanId: string): Promise<Response> {
  const claims = await sessionClaims(request, env);
  const binding = coordinator(env);
  if (claims === null || binding === undefined) return json({ error: "unauthorized" }, 401);
  return binding.fetch(new Request(`https://coordinator/results/${scanId}`, {
    headers: { "x-watchdog-session": claims.sid },
  }));
}

export async function handleRequest(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  if (url.pathname === "/api/health" && request.method === "GET") {
    return json({ status: "ok", service: "watch-dog" });
  }

  if (url.pathname === "/api/login" && request.method === "POST") return login(request, env);
  if (url.pathname === "/api/session" && request.method === "GET") return sessionStatus(request, env);
  if (url.pathname === "/api/logout" && request.method === "POST") return logout(request, env);
  const result = /^\/api\/results\/([a-f0-9]{32})$/u.exec(url.pathname);
  if (result !== null && request.method === "GET") return getResult(request, env, result[1] as string);

  if (url.pathname.startsWith("/api/")) {
    return json({ error: "not_configured" }, 503);
  }

  if (env.ASSETS) return env.ASSETS.fetch(request);
  return new Response("Watch Dog asset binding is unavailable", {
    status: 503,
    headers: { "content-type": "text/plain; charset=utf-8" },
  });
}

export default { fetch: handleRequest };
export { SessionCoordinator };
