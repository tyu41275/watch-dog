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
  type CoordinatorStub,
  SessionCoordinator,
} from "./coordinator.js";
import type { ScanResult } from "../shared/contracts.js";
import {
  PASTE_LIMITS,
  executePasteScan,
  parsePasteRequest,
} from "./fetch/paste.js";
import {
  LIVE_LIMITS,
  executeLiveScan,
  parseLiveRequest,
} from "./live.js";
import { GoogleSafeBrowsingAdapter } from "./providers/google.js";

interface AssetBinding {
  fetch(request: Request): Promise<Response>;
}

export interface Env {
  ASSETS?: AssetBinding;
  ADMIN_USERNAME?: string;
  ADMIN_PASSWORD?: string;
  SESSION_SIGNING_KEY?: string;
  GOOGLE_SAFE_BROWSING_ENABLED?: string;
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
  try {
    return env.SESSION_COORDINATOR?.get(env.SESSION_COORDINATOR.idFromName("global"));
  } catch {
    return undefined;
  }
}

function googleProvider(env: Env, request: Request): GoogleSafeBrowsingAdapter {
  return new GoogleSafeBrowsingAdapter(
    env.GOOGLE_SAFE_BROWSING_ENABLED === "true" &&
      request.headers.get("x-watchdog-provider-consent") === "google_safe_browsing"
      ? env.GOOGLE_SAFE_BROWSING_API_KEY
      : undefined,
  );
}

async function boundedText(request: Request, maximum: number): Promise<string | null> {
  const declared = Number(request.headers.get("content-length") ?? 0);
  if (!Number.isSafeInteger(declared) || declared < 0 || declared > maximum) return null;
  const reader = request.body?.getReader();
  if (reader === undefined) return "";
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > maximum) {
        await reader.cancel();
        return null;
      }
      chunks.push(value);
    }
    const bytes = new Uint8Array(size);
    let offset = 0;
    for (const chunk of chunks) {
      bytes.set(chunk, offset);
      offset += chunk.byteLength;
    }
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    return null;
  } finally {
    reader.releaseLock();
  }
}

async function bodyCredentials(request: Request) {
  const text = await boundedText(request, 4_096);
  if (text === null) return null;
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
  let decision: { allowed: boolean; retry_after_seconds: number };
  try {
    const attempt = await binding.fetch(new Request("https://coordinator/throttle/attempt", {
      method: "POST",
      body: JSON.stringify({ key }),
    }));
    const body = await attempt.json() as { allowed?: unknown; retry_after_seconds?: unknown };
    if (!attempt.ok || typeof body.allowed !== "boolean" || typeof body.retry_after_seconds !== "number") {
      return json({ error: "invalid_credentials" }, 401);
    }
    decision = { allowed: body.allowed, retry_after_seconds: body.retry_after_seconds };
  } catch {
    return json({ error: "invalid_credentials" }, 401);
  }
  if (!decision.allowed) {
    const denied = json({ error: "invalid_credentials" }, 429);
    denied.headers.set("retry-after", String(decision.retry_after_seconds ?? 600));
    return denied;
  }
  if (!await verifyCredentials(credentials.username, credentials.password, secrets)) {
    return json({ error: "invalid_credentials" }, 401);
  }
  try {
    const reset = await binding.fetch(new Request("https://coordinator/throttle/reset", {
      method: "POST",
      body: JSON.stringify({ key }),
    }));
    if (!reset.ok || (await reset.json() as { ok?: unknown }).ok !== true) {
      return json({ error: "invalid_credentials" }, 401);
    }
  } catch {
    return json({ error: "invalid_credentials" }, 401);
  }
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
    : json({
        authenticated: true,
        csrf_token: claims.csrf,
        expires_at: new Date(claims.exp * 1_000).toISOString(),
      });
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

async function storeResult(
  binding: CoordinatorStub,
  sessionId: string,
  result: ScanResult,
): Promise<string> {
  const response = await binding.fetch(new Request("https://coordinator/results", {
    method: "POST",
    body: JSON.stringify({ session_id: sessionId, result }),
  }));
  if (!response.ok) throw new TypeError("result coordination failed");
  const body = await response.json() as { scan_id?: unknown };
  if (typeof body.scan_id !== "string" || !/^[a-f0-9]{32}$/u.test(body.scan_id)) {
    throw new TypeError("result coordination malformed");
  }
  return body.scan_id;
}

async function pasteScan(request: Request, env: Env): Promise<Response> {
  const claims = await sessionClaims(request, env);
  const binding = coordinator(env);
  if (
    claims === null || binding === undefined || !sameOriginMutation(request) ||
    request.headers.get(CSRF_HEADER) !== claims.csrf
  ) return json({ error: "unauthorized" }, 401);
  const text = await boundedText(request, PASTE_LIMITS.max_request_bytes);
  if (text === null) return json({ error: "invalid_request" }, 400);
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch {
    return json({ error: "invalid_request" }, 400);
  }
  const input = parsePasteRequest(value);
  if (input === null) return json({ error: "invalid_request" }, 400);
  try {
    const receipt = await executePasteScan(input, {
      store: (result) => storeResult(binding, claims.sid, result),
      provider: googleProvider(env, request),
    });
    return json(receipt, 201);
  } catch {
    return json({ error: "scan_unavailable" }, 503);
  }
}

async function liveScan(request: Request, env: Env): Promise<Response> {
  const claims = await sessionClaims(request, env);
  const binding = coordinator(env);
  if (
    claims === null || binding === undefined || !sameOriginMutation(request) ||
    request.headers.get(CSRF_HEADER) !== claims.csrf
  ) return json({ error: "unauthorized" }, 401);
  const text = await boundedText(request, LIVE_LIMITS.max_request_bytes);
  if (text === null) return json({ error: "invalid_request" }, 400);
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch {
    return json({ error: "invalid_request" }, 400);
  }
  const input = parseLiveRequest(value, new URL(request.url).origin);
  if (input === null) return json({ error: "invalid_request" }, 400);
  try {
    const receipt = await executeLiveScan(input, {
      store: (result) => storeResult(binding, claims.sid, result),
      provider: googleProvider(env, request),
    });
    return json(receipt, 201);
  } catch {
    return json({ error: "scan_unavailable" }, 503);
  }
}

export async function handleRequest(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  if (url.pathname === "/api/health" && request.method === "GET") {
    return json({ status: "ok", service: "watch-dog" });
  }

  if (url.pathname === "/api/login" && request.method === "POST") return login(request, env);
  if (url.pathname === "/api/session" && request.method === "GET") return sessionStatus(request, env);
  if (url.pathname === "/api/logout" && request.method === "POST") return logout(request, env);
  if (url.pathname === "/api/scans/paste" && request.method === "POST") return pasteScan(request, env);
  if (url.pathname === "/api/scans/live" && request.method === "POST") return liveScan(request, env);
  const result = /^\/api\/results\/([a-f0-9]{32})$/u.exec(url.pathname);
  if (result !== null && request.method === "GET") return getResult(request, env, result[1] as string);

  if (url.pathname.startsWith("/api/")) {
    return json({ error: "not_configured" }, 503);
  }

  if (
    request.method === "GET" &&
    (url.pathname === "/reference.html" || (url.pathname === "/reference" && url.search !== ""))
  ) {
    url.pathname = "/reference";
    url.search = "";
    return Response.redirect(url, 308);
  }

  if (env.ASSETS) {
    if (url.pathname === "/" && request.method === "GET") {
      const assetUrl = new URL(request.url);
      assetUrl.pathname = "/index.html";
      return env.ASSETS.fetch(new Request(assetUrl, request));
    }
    if (url.pathname === "/reference" && request.method === "GET") {
      const assetUrl = new URL(request.url);
      assetUrl.pathname = "/reference.html";
      return env.ASSETS.fetch(new Request(assetUrl, request));
    }
    return env.ASSETS.fetch(request);
  }
  return new Response("Watch Dog asset binding is unavailable", {
    status: 503,
    headers: { "content-type": "text/plain; charset=utf-8" },
  });
}

export default { fetch: handleRequest };
export { SessionCoordinator };
