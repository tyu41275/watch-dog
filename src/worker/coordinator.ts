import { parseScanResult, type ScanResult } from "../shared/contracts.js";
import {
  createScanMachine,
  reduceScanMachine,
  scanJournalEntry,
  type ScanExchange,
} from "../shared/scan-machine.js";

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

type StoredRecord = {
  session_id: string;
  expires_at: number;
} & ({ kind: "result"; result: ScanResult } | { kind: "receipt"; exchange: ScanExchange });
interface Snapshot { records: Map<string, StoredRecord> }
export type ResultLookup =
  | { status: "ok"; result: ScanResult }
  | { status: "missing" | "expired" | "unauthorized" };
export type ReceiptLookup =
  | { status: "ok"; receipt: ScanExchange["receipt"] }
  | { status: "missing" | "expired" | "unauthorized" };
type LookupFailure = { status: "missing" | "expired" | "unauthorized" };

function same(left: unknown, right: unknown): boolean {
  if (Object.is(left, right)) return true;
  if (typeof left !== "object" || left === null || typeof right !== "object" || right === null) return false;
  if (Array.isArray(left) || Array.isArray(right)) return Array.isArray(left) && Array.isArray(right) &&
    left.length === right.length && left.every((value, index) => same(value, right[index]));
  const a = left as Record<string, unknown>, b = right as Record<string, unknown>;
  const keys = Object.keys(a);
  return keys.length === Object.keys(b).length && keys.every((key) => Object.hasOwn(b, key) && same(a[key], b[key]));
}

function isLive(record: StoredRecord, nowMs: number): boolean {
  return record.expires_at > nowMs;
}

function hasLiveCollision(records: Map<string, StoredRecord>, id: string, nowMs: number): boolean {
  const record = records.get(id); return record !== undefined && isLive(record, nowMs); }

function reclaim(records: Map<string, StoredRecord>, nowMs: number): void {
  const batch: [string, StoredRecord][] = []; for (const entry of records) { batch.push(entry); if (batch.length === 64) break; }
  for (const [id, record] of batch) {
    records.delete(id);
    if (isLive(record, nowMs)) records.set(id, record);
  }
}

function generatedId(): string {
  const id = crypto.randomUUID().replaceAll("-", "").toLowerCase();
  if (!/^[a-f0-9]{32}$/u.test(id)) throw new TypeError("invalid generated id");
  return id;
}

export class CoordinatorCore {
  private readonly throttles = new Map<string, ThrottleRecord>();
  private snapshot: Snapshot = { records: new Map() };

  attemptLogin(key: string, nowMs: number) {
    const next = advanceThrottle(this.throttles.get(key), nowMs);
    this.throttles.set(key, next.record);
    return next.decision;
  }

  resetLogin(key: string): void {
    this.throttles.delete(key);
  }

  putLiveResult(sessionId: string, value: unknown, nowMs: number): string {
    const result = parseScanResult(value);
    if (result.mode !== "live_page") throw new TypeError("live result mode required");
    const id = generatedId();
    if (hasLiveCollision(this.snapshot.records, id, nowMs)) throw new TypeError("id collision");
    const stored = structuredClone({ ...result, scan_id: id });
    const records = new Map(this.snapshot.records);
    reclaim(records, nowMs);
    records.set(id, { kind: "result", session_id: sessionId,
      expires_at: nowMs + RESULT_TTL_SECONDS * 1_000, result: stored });
    this.snapshot = { records };
    return id;
  }

  commitPaste(sessionId: string, input: unknown, journal: unknown, nowMs: number): ScanExchange["receipt"] {
    if (!Array.isArray(journal)) throw new TypeError("journal must be an array");
    let machine = createScanMachine(input);
    for (const raw of journal) {
      if (typeof raw !== "object" || raw === null || Array.isArray(raw)) throw new TypeError("invalid entry");
      const data = raw as Record<string, unknown>;
      if (Object.keys(data).length !== 2 || !("effect" in data) || !("fact" in data)) throw new TypeError("invalid entry");
      const entry = scanJournalEntry(data.effect, data.fact);
      if (entry.effect.kind === "ALLOCATE_IDS" || machine.pending === null ||
        !same(machine.pending, entry.effect)) throw new TypeError("journal effect mismatch");
      machine = reduceScanMachine(machine, entry.fact);
    }
    const effect = machine.pending;
    if (machine.phase !== "AWAIT_IDS" || effect?.kind !== "ALLOCATE_IDS") {
      throw new TypeError("paste prefix is incomplete or over-complete");
    }
    const ids = Array.from({ length: effect.count }, generatedId);
    if (new Set(ids).size !== ids.length ||
      ids.some((id) => hasLiveCollision(this.snapshot.records, id, nowMs))) {
      throw new TypeError("id collision");
    }
    machine = reduceScanMachine(machine, { kind: "IDS_ALLOCATED", effect_id: effect.id, ids });
    const exchange = machine.exchange;
    if (machine.phase !== "DONE" || exchange === null || exchange.receipt.receipt_id !== ids[0] ||
      exchange.entries.some((entry, index) => entry.result_id !== ids[index + 1] ||
        entry.result.scan_id !== ids[index + 1])) throw new TypeError("allocation binding failed");
    const prepared = structuredClone(exchange);
    const records = new Map(this.snapshot.records);
    reclaim(records, nowMs);
    const expiresAt = nowMs + RESULT_TTL_SECONDS * 1_000;
    records.set(ids[0]!, { kind: "receipt", session_id: sessionId, expires_at: expiresAt,
      exchange: prepared });
    for (const entry of prepared.entries) records.set(entry.result_id, {
      kind: "result", session_id: sessionId, expires_at: expiresAt, result: entry.result,
    });
    const receipt = structuredClone(prepared.receipt);
    this.snapshot = { records };
    return receipt;
  }

  private lookup(sessionId: string, id: string, nowMs: number): StoredRecord | LookupFailure {
    const record = this.snapshot.records.get(id);
    if (record === undefined) return { status: "missing" };
    if (!isLive(record, nowMs)) {
      const records = new Map(this.snapshot.records);
      records.delete(id);
      this.snapshot = { records };
      return { status: "expired" };
    }
    if (record.session_id !== sessionId) return { status: "unauthorized" };
    return record;
  }

  getResult(sessionId: string, scanId: string, nowMs: number): ResultLookup {
    const record = this.lookup(sessionId, scanId, nowMs);
    if ("status" in record) return record;
    return record.kind === "result" ? { status: "ok", result: structuredClone(record.result) }
      : { status: "missing" };
  }

  getReceipt(sessionId: string, receiptId: string, nowMs: number): ReceiptLookup {
    const record = this.lookup(sessionId, receiptId, nowMs);
    if ("status" in record) return record;
    return record.kind === "receipt"
      ? { status: "ok", receipt: structuredClone(record.exchange.receipt) }
      : { status: "missing" };
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
function exact(body: Record<string, unknown> | null, keys: string[]): body is Record<string, unknown> {
  if (body === null) return false;
  const actual = Object.keys(body).sort();
  return actual.length === keys.length && actual.every((key, index) => key === [...keys].sort()[index]);
}
const session = (value: unknown): value is string =>
  typeof value === "string" && /^[A-Za-z0-9_-]{32}$/u.test(value);

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
    if (url.pathname === "/live-results" && request.method === "POST") {
      const body = await jsonObject(request);
      if (!exact(body, ["version", "session_id", "result"]) || body.version !== 1 || !session(body.session_id)) return response({ error: "invalid_request" }, 400);
      try {
        return response({ scan_id: this.core.putLiveResult(body.session_id, body.result, nowMs),
          expires_in_seconds: RESULT_TTL_SECONDS }, 201);
      } catch { return response({ error: "invalid_request" }, 400); }
    }
    if (url.pathname === "/paste-exchanges" && request.method === "POST") {
      const body = await jsonObject(request);
      if (!exact(body, ["version", "session_id", "input", "journal"]) || body.version !== 1 || !session(body.session_id)) return response({ error: "invalid_request" }, 400);
      try {
        return response({ receipt: this.core.commitPaste(body.session_id, body.input, body.journal, nowMs),
          expires_in_seconds: RESULT_TTL_SECONDS }, 201);
      } catch { return response({ error: "invalid_request" }, 400); }
    }
    const match = /^\/results\/([a-f0-9]{32})$/u.exec(url.pathname);
    if (match !== null && request.method === "GET") {
      const sessionId = request.headers.get("x-watchdog-session");
      if (sessionId === null) return response({ error: "unauthorized" }, 401);
      const lookup = this.core.getResult(sessionId, match[1]!, nowMs);
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
