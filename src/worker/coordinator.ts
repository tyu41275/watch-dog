import { parseScanResult, type ScanResult } from "../shared/contracts.js";

export const THROTTLE_WINDOW_MS = 5 * 60 * 1_000;
export const THROTTLE_BLOCK_MS = 10 * 60 * 1_000;
export const THROTTLE_ATTEMPTS = 5;
export const RESULT_TTL_SECONDS = 10 * 60;

interface ThrottleRecord {
  started_at: number;
  attempts: number;
  blocked_until: number;
}

function advanceThrottle(
  record: ThrottleRecord | undefined,
  nowMs: number,
): { decision: { allowed: boolean; retry_after_seconds: number }; record: ThrottleRecord } {
  if (record !== undefined && record.blocked_until > nowMs) {
    return {
      decision: {
        allowed: false,
        retry_after_seconds: Math.ceil((record.blocked_until - nowMs) / 1_000),
      },
      record,
    };
  }
  const current = record === undefined || nowMs - record.started_at >= THROTTLE_WINDOW_MS
    ? { started_at: nowMs, attempts: 0, blocked_until: 0 }
    : { ...record };
  current.attempts += 1;
  if (current.attempts > THROTTLE_ATTEMPTS) {
    current.blocked_until = nowMs + THROTTLE_BLOCK_MS;
    return {
      decision: { allowed: false, retry_after_seconds: THROTTLE_BLOCK_MS / 1_000 },
      record: current,
    };
  }
  return { decision: { allowed: true, retry_after_seconds: 0 }, record: current };
}

interface ResultRecord {
  session_id: string;
  expires_at: number;
  result: ScanResult;
}

export type ResultLookup =
  | { status: "ok"; result: ScanResult }
  | { status: "missing" | "expired" | "unauthorized" };

export class CoordinatorCore {
  private readonly throttles = new Map<string, ThrottleRecord>();
  private readonly results = new Map<string, ResultRecord>();

  attemptLogin(key: string, nowMs: number): { allowed: boolean; retry_after_seconds: number } {
    const next = advanceThrottle(this.throttles.get(key), nowMs);
    this.throttles.set(key, next.record);
    return next.decision;
  }

  resetLogin(key: string): void {
    this.throttles.delete(key);
  }

  putResult(sessionId: string, result: ScanResult, nowMs: number): string {
    const scanId = crypto.randomUUID().replaceAll("-", "");
    this.results.set(scanId, {
      session_id: sessionId,
      expires_at: nowMs + RESULT_TTL_SECONDS * 1_000,
      result: structuredClone({ ...result, scan_id: scanId }),
    });
    return scanId;
  }

  getResult(sessionId: string, scanId: string, nowMs: number): ResultLookup {
    const record = this.results.get(scanId);
    if (record === undefined) return { status: "missing" };
    if (record.expires_at <= nowMs) {
      this.results.delete(scanId);
      return { status: "expired" };
    }
    if (record.session_id !== sessionId) return { status: "unauthorized" };
    return { status: "ok", result: structuredClone(record.result) };
  }
}

interface DurableStorage {
  get<T>(key: string): Promise<T | undefined>;
  put(key: string, value: unknown): Promise<void>;
  delete(key: string): Promise<boolean>;
}

interface DurableState {
  storage: DurableStorage;
}

function response(body: unknown, status = 200): Response {
  return Response.json(body, {
    status,
    headers: { "cache-control": "no-store", "content-type": "application/json" },
  });
}

async function jsonObject(request: Request): Promise<Record<string, unknown> | null> {
  try {
    const value = await request.json();
    return typeof value === "object" && value !== null && !Array.isArray(value)
      ? value as Record<string, unknown>
      : null;
  } catch {
    return null;
  }
}

/** Cloudflare Durable Object: hashed throttle state may persist; scan results never do. */
export class SessionCoordinator {
  private readonly core = new CoordinatorCore();

  constructor(private readonly state: DurableState) {}

  private async attempt(key: string, nowMs: number) {
    const storageKey = `throttle:${key}`;
    const stored = await this.state.storage.get<ThrottleRecord>(storageKey);
    const next = advanceThrottle(stored, nowMs);
    await this.state.storage.put(storageKey, next.record);
    return next.decision;
  }

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const nowMs = Date.now();
    if (url.pathname === "/throttle/attempt" && request.method === "POST") {
      const body = await jsonObject(request);
      const key = body?.key;
      if (typeof key !== "string" || !/^[A-Za-z0-9_-]{43}$/u.test(key)) {
        return response({ error: "invalid_request" }, 400);
      }
      return response(await this.attempt(key, nowMs));
    }
    if (url.pathname === "/throttle/reset" && request.method === "POST") {
      const body = await jsonObject(request);
      const key = body?.key;
      if (typeof key !== "string") return response({ error: "invalid_request" }, 400);
      this.core.resetLogin(key);
      await this.state.storage.delete(`throttle:${key}`);
      return response({ ok: true });
    }
    if (url.pathname === "/results" && request.method === "POST") {
      const body = await jsonObject(request);
      if (
        typeof body?.session_id !== "string" ||
        !/^[A-Za-z0-9_-]{32}$/u.test(body.session_id)
      ) {
        return response({ error: "invalid_request" }, 400);
      }
      try {
        const result = parseScanResult(body.result);
        return response({
          scan_id: this.core.putResult(body.session_id, result, nowMs),
          expires_in_seconds: RESULT_TTL_SECONDS,
        }, 201);
      } catch {
        return response({ error: "invalid_request" }, 400);
      }
    }
    const match = /^\/results\/([a-f0-9]{32})$/u.exec(url.pathname);
    if (match !== null && request.method === "GET") {
      const sessionId = request.headers.get("x-watchdog-session");
      if (sessionId === null) return response({ error: "unauthorized" }, 401);
      const lookup = this.core.getResult(sessionId, match[1] as string, nowMs);
      if (lookup.status === "ok") return response(lookup);
      return response({ error: lookup.status }, lookup.status === "unauthorized" ? 403 : 404);
    }
    return response({ error: "not_found" }, 404);
  }
}

export interface CoordinatorStub {
  fetch(request: Request): Promise<Response>;
}

export interface CoordinatorNamespace {
  idFromName(name: string): unknown;
  get(id: unknown): CoordinatorStub;
}
