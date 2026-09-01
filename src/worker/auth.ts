export const SESSION_COOKIE = "__Host-watchdog_session";
export const SESSION_TTL_SECONDS = 15 * 60;
export const CSRF_HEADER = "x-watchdog-csrf";

export interface AuthEnvironment {
  ADMIN_USERNAME?: string;
  ADMIN_PASSWORD?: string;
  SESSION_SIGNING_KEY?: string;
}

export interface AuthSecrets {
  username: string;
  password: string;
  signingKey: string;
}

export interface SessionClaims {
  v: 1;
  sid: string;
  csrf: string;
  exp: number;
}

const encoder = new TextEncoder();

function bytesToBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
}

function base64UrlToBytes(value: string): Uint8Array | null {
  if (!/^[A-Za-z0-9_-]+$/u.test(value)) return null;
  try {
    const padded = value.replaceAll("-", "+").replaceAll("_", "/")
      .padEnd(Math.ceil(value.length / 4) * 4, "=");
    return Uint8Array.from(atob(padded), (character) => character.charCodeAt(0));
  } catch {
    return null;
  }
}

function randomToken(bytes = 24): string {
  return bytesToBase64Url(crypto.getRandomValues(new Uint8Array(bytes)));
}

async function hmac(key: string, value: string): Promise<Uint8Array> {
  const imported = await crypto.subtle.importKey(
    "raw",
    encoder.encode(key),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  return new Uint8Array(await crypto.subtle.sign("HMAC", imported, encoder.encode(value)));
}

function equal(left: Uint8Array, right: Uint8Array): boolean {
  let difference = left.length ^ right.length;
  const length = Math.max(left.length, right.length);
  for (let index = 0; index < length; index += 1) {
    difference |= (left[index] ?? 0) ^ (right[index] ?? 0);
  }
  return difference === 0;
}

export function readAuthSecrets(env: AuthEnvironment): AuthSecrets | null {
  const username = env.ADMIN_USERNAME?.trim();
  const password = env.ADMIN_PASSWORD;
  const signingKey = env.SESSION_SIGNING_KEY;
  if (!username || !password || !signingKey || signingKey.length < 32) return null;
  return { username, password, signingKey };
}

export async function verifyCredentials(
  suppliedUsername: string,
  suppliedPassword: string,
  secrets: AuthSecrets,
): Promise<boolean> {
  const [supplied, expected] = await Promise.all([
    hmac(secrets.signingKey, `${suppliedUsername}\u0000${suppliedPassword}`),
    hmac(secrets.signingKey, `${secrets.username}\u0000${secrets.password}`),
  ]);
  return equal(supplied, expected);
}

async function signClaims(claims: SessionClaims, signingKey: string): Promise<string> {
  const payload = bytesToBase64Url(encoder.encode(JSON.stringify(claims)));
  const signature = bytesToBase64Url(await hmac(signingKey, payload));
  return `${payload}.${signature}`;
}

export async function createSession(
  secrets: AuthSecrets,
  nowMs = Date.now(),
): Promise<{ claims: SessionClaims; token: string; cookie: string }> {
  const claims: SessionClaims = {
    v: 1,
    sid: randomToken(),
    csrf: randomToken(),
    exp: Math.floor(nowMs / 1_000) + SESSION_TTL_SECONDS,
  };
  const token = await signClaims(claims, secrets.signingKey);
  return {
    claims,
    token,
    cookie: [
      `${SESSION_COOKIE}=${token}`,
      "Path=/",
      "HttpOnly",
      "Secure",
      "SameSite=Strict",
      `Max-Age=${SESSION_TTL_SECONDS}`,
    ].join("; "),
  };
}

function cookieValue(header: string | null, name: string): string | null {
  if (header === null) return null;
  for (const part of header.split(";")) {
    const [candidate, ...rest] = part.trim().split("=");
    if (candidate === name) return rest.join("=");
  }
  return null;
}

export async function verifySession(
  cookieHeader: string | null,
  secrets: AuthSecrets,
  nowMs = Date.now(),
): Promise<SessionClaims | null> {
  const token = cookieValue(cookieHeader, SESSION_COOKIE);
  if (token === null || token.length > 2_048) return null;
  const segments = token.split(".");
  if (segments.length !== 2) return null;
  const payload = segments[0];
  const signature = segments[1];
  if (payload === undefined || signature === undefined) return null;
  const supplied = base64UrlToBytes(signature);
  if (supplied === null || !equal(supplied, await hmac(secrets.signingKey, payload))) return null;
  const decoded = base64UrlToBytes(payload);
  if (decoded === null) return null;
  try {
    const claims = JSON.parse(new TextDecoder().decode(decoded)) as Partial<SessionClaims>;
    if (
      claims.v !== 1 ||
      typeof claims.sid !== "string" ||
      !/^[A-Za-z0-9_-]{32}$/u.test(claims.sid) ||
      typeof claims.csrf !== "string" ||
      !/^[A-Za-z0-9_-]{32}$/u.test(claims.csrf) ||
      !Number.isSafeInteger(claims.exp) ||
      (claims.exp as number) <= Math.floor(nowMs / 1_000)
    ) return null;
    return claims as SessionClaims;
  } catch {
    return null;
  }
}

export function expireSessionCookie(): string {
  return `${SESSION_COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`;
}

export function sameOriginMutation(request: Request): boolean {
  const origin = request.headers.get("origin");
  if (origin === null) return false;
  try {
    return new URL(origin).origin === new URL(request.url).origin;
  } catch {
    return false;
  }
}

export async function throttleFingerprint(
  ip: string,
  username: string,
  signingKey: string,
): Promise<string> {
  return bytesToBase64Url(await hmac(signingKey, `throttle\u0000${ip}\u0000${username}`));
}
