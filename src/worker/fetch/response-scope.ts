export type Fetcher = (input: string, init?: RequestInit) => Promise<Response>;
declare const HANDLE: unique symbol;
export type ResponseHandle = Readonly<{ [HANDLE]: true }>;
export type AcquireFact =
  | { ok: true; handle: ResponseHandle; completed_at: number }
  | { ok: false; failure: "timeout" | "network_error" | "capacity" | "sealed"; completed_at: number };
export interface HeaderAtom { value: string | null; overflow: boolean }
export type MetadataFact =
  | { ok: true; status: number; headers: Record<string, HeaderAtom>; handle: ResponseHandle }
  | { ok: false };
export type ReadFact =
  | { ok: true; bytes: Uint8Array; completed_at: number }
  | { ok: false; failure: "timeout" | "limit" | "invalid"; completed_at: number };
type CellState = "PENDING" | "SEALED_PENDING" | "OWNED" | "READING" | "CONSUMED" | "CANCEL_ISSUED" | "CLOSED_NO_RESPONSE";
interface Cell { state: CellState; controller: AbortController; response: Response | undefined;
  reader: ReadableStreamDefaultReader<Uint8Array> | undefined; timer: ReturnType<typeof setTimeout> | undefined;
  wake: (() => void) | undefined; }
export interface ScopeReceipt { state: "SEALED"; live_handles: number; pending_tickets: number;
  cancel_issued: number; cancel_settled: number; cancel_pending: number; cancel_rejected: number; }
export function createResponseScope(fetcher: Fetcher, now: () => number = Date.now) {
  let state: "OPEN" | "SEALING" | "SEALED" = "OPEN";
  let cancelIssued = 0; let cancelSettled = 0; let cancelRejected = 0;
  const cells = new Set<Cell>();
  const handles = new WeakMap<object, Cell>();
  const observeCancel = (run: () => void | Promise<void>) => {
    cancelIssued += 1;
    try {
      const result = run();
      if (result === undefined) cancelSettled += 1; else void Promise.resolve(result).then(() => { cancelSettled += 1; }, () => { cancelSettled += 1; cancelRejected += 1; });
    } catch { cancelSettled += 1; cancelRejected += 1; }
  };
  const release = (cell: Cell, response = cell.response) => {
    if (cell.state === "CANCEL_ISSUED" || cell.state === "CONSUMED" || cell.state === "CLOSED_NO_RESPONSE") return;
    cell.state = "CANCEL_ISSUED";
    if (cell.timer !== undefined) clearTimeout(cell.timer);
    cells.delete(cell);
    const reader = cell.reader;
    cell.reader = undefined;
    cell.response = undefined;
    cell.controller.abort();
    const wake = cell.wake;
    cell.wake = undefined;
    if (reader !== undefined) {
      observeCancel(() => reader.cancel());
      try { reader.releaseLock(); } catch { /* already released */ }
    } else if (response?.body !== null && response?.body !== undefined) {
      observeCancel(() => response.body!.cancel());
    } else { cancelIssued += 1; cancelSettled += 1; }
    wake?.();
  };
  const issueHandle = (cell: Cell): ResponseHandle => {
    const handle = Object.freeze({}) as ResponseHandle;
    handles.set(handle, cell);
    return handle;
  };
  const take = (handle: ResponseHandle): Cell | undefined => {
    const cell = handles.get(handle);
    handles.delete(handle);
    return cell?.state === "OWNED" ? cell : undefined;
  };
  const request = (input: string, init: RequestInit, deadline: number): Promise<AcquireFact> => {
    const completed = () => now();
    if (state !== "OPEN") return Promise.resolve({ ok: false, failure: "sealed", completed_at: completed() });
    const startedAt = completed();
    if (startedAt >= deadline) return Promise.resolve({ ok: false, failure: "timeout", completed_at: startedAt });
    if (cells.size >= 2) return Promise.resolve({ ok: false, failure: "capacity", completed_at: completed() });
    const cell: Cell = { state: "PENDING", controller: new AbortController(), response: undefined, reader: undefined, timer: undefined, wake: undefined };
    cells.add(cell);
    return new Promise((resolve) => {
      let settled = false;
      const finish = (fact: AcquireFact) => { if (!settled) { settled = true; cell.wake = undefined; resolve(fact); } };
      cell.wake = () => finish({ ok: false, failure: "timeout", completed_at: completed() });
      let pending: Promise<Response>;
      try { pending = fetcher(input, { ...init, signal: cell.controller.signal }); }
      catch (error) { pending = Promise.reject(error); }
      void Promise.resolve(pending).then((response) => {
        const at = completed();
        if (cell.state === "PENDING" && state === "OPEN" && !settled && at <= deadline) {
          if (cell.timer !== undefined) clearTimeout(cell.timer);
          cell.state = "OWNED";
          cell.response = response;
          finish({ ok: true, handle: issueHandle(cell), completed_at: at });
        } else { release(cell, response); finish({ ok: false, failure: "timeout", completed_at: at }); }
      }, () => {
        const at = completed();
        if (cell.timer !== undefined) clearTimeout(cell.timer);
        cell.state = "CLOSED_NO_RESPONSE";
        cells.delete(cell);
        finish({ ok: false, failure: settled ? "timeout" : "network_error", completed_at: at });
      });
      if (Number.isFinite(deadline)) cell.timer = setTimeout(() => {
        if (cell.state !== "PENDING") return;
        cell.state = "SEALED_PENDING"; cell.controller.abort(); cell.wake?.();
      }, Math.max(0, deadline - completed()));
    });
  };
  const metadata = (handle: ResponseHandle, limits: Record<string, number>): MetadataFact => {
    const cell = take(handle);
    if (cell?.response === undefined) return { ok: false };
    const headers: Record<string, HeaderAtom> = {};
    for (const [name, maximum] of Object.entries(limits)) {
      const value = cell.response.headers.get(name);
      headers[name] = value !== null && value.length > maximum
        ? { value: null, overflow: true } : { value, overflow: false };
    }
    return { ok: true, status: cell.response.status, headers, handle: issueHandle(cell) };
  };
  const read = async (handle: ResponseHandle, maximum: number, deadline: number): Promise<ReadFact> => {
    const cell = take(handle);
    if (cell?.response === undefined) return { ok: false, failure: "invalid", completed_at: now() };
    if (now() >= deadline) { release(cell); return { ok: false, failure: "timeout", completed_at: now() }; }
    try { cell.reader = cell.response.body?.getReader(); } catch { release(cell); }
    if (cell.reader === undefined) { release(cell); return { ok: false, failure: "invalid", completed_at: now() }; }
    cell.state = "READING";
    const chunks: Uint8Array[] = [];
    let size = 0; let readFailed = false;
    while (cell.state === "READING") {
      const part = await new Promise<ReadableStreamReadResult<Uint8Array> | null>((resolve) => {
        let done = false;
        const finish = (value: ReadableStreamReadResult<Uint8Array> | null) => { if (!done) { done = true; cell.wake = undefined; resolve(value); } };
        cell.wake = () => finish(null);
        let pending: Promise<ReadableStreamReadResult<Uint8Array>>;
        try { pending = cell.reader!.read(); } catch { pending = Promise.reject(); }
        void Promise.resolve(pending).then((value) => now() <= deadline ? finish(value) : (release(cell), finish(null)), () => { readFailed = true; release(cell); finish(null); });
        if (Number.isFinite(deadline)) cell.timer = setTimeout(() => { release(cell); finish(null); }, Math.max(0, deadline - now()));
      });
      if (part === null) return { ok: false, failure: readFailed ? "invalid" : "timeout", completed_at: now() };
      if (cell.timer !== undefined) clearTimeout(cell.timer);
      if (part.done) break;
      size += part.value.byteLength;
      if (size > maximum) { release(cell); return { ok: false, failure: "limit", completed_at: now() }; }
      chunks.push(part.value);
    }
    try { cell.reader.releaseLock(); } catch { /* already released */ }
    cell.state = "CONSUMED"; cells.delete(cell); cell.reader = undefined; cell.response = undefined;
    const bytes = new Uint8Array(size);
    let offset = 0;
    for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
    return { ok: true, bytes, completed_at: now() };
  };
  const discard = (handle: ResponseHandle): boolean => {
    const cell = take(handle);
    if (cell === undefined) return false;
    release(cell); return true;
  };
  const receipt = (): ScopeReceipt => Object.freeze({ state: "SEALED", live_handles: [...cells].filter((cell) => cell.state === "OWNED" || cell.state === "READING").length, pending_tickets: [...cells].filter((cell) => cell.state === "SEALED_PENDING").length, cancel_issued: cancelIssued, cancel_settled: cancelSettled, cancel_pending: cancelIssued - cancelSettled, cancel_rejected: cancelRejected });
  const seal = (): ScopeReceipt => {
    if (state === "SEALED") return receipt();
    state = "SEALING";
    for (const cell of [...cells]) {
      if (cell.state === "PENDING") {
        cell.state = "SEALED_PENDING";
        if (cell.timer !== undefined) clearTimeout(cell.timer);
        cell.controller.abort(); cell.wake?.();
      } else if (cell.state === "OWNED" || cell.state === "READING") release(cell);
    }
    state = "SEALED"; return receipt();
  };
  return Object.freeze({ request, metadata, read, discard, seal });
}
