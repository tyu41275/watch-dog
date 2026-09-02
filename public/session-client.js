import { decodeLiveExchange, presentExchange } from "./results.js";
export const SESSION_LIMITS = Object.freeze({ operationMilliseconds: 15_000,
  resultCount: 16, scanIdCharacters: 32 });
const clone = (value) => structuredClone(value);
const aborted = (signal, message = "operation cancelled") => signal.reason instanceof Error
  ? signal.reason : new DOMException(message, "AbortError");
function abortable(value, signal) {
  signal.throwIfAborted();
  return new Promise((resolve, reject) => {
    let settled = false;
    const finish = (handler, result) => {
      if (settled) return;
      settled = true; signal.removeEventListener("abort", cancel);
      handler(result);
    };
    const cancel = () => finish(reject, aborted(signal));
    signal.addEventListener("abort", cancel, { once: true });
    Promise.resolve(value).then(
      (result) => finish(resolve, result), (error) => finish(reject, error));
  });
}
function exact(value, keys) {
  return typeof value === "object" && value !== null && !Array.isArray(value) &&
    Object.keys(value).sort().join() === [...keys].sort().join();
}
function parseSession(value) {
  if (!exact(value, ["authenticated", "csrf_token", "expires_at"]) ||
    value.authenticated !== true || typeof value.csrf_token !== "string" ||
    !/^[A-Za-z0-9_-]{32}$/u.test(value.csrf_token) ||
    typeof value.expires_at !== "string" || !Number.isFinite(Date.parse(value.expires_at)) ||
    new Date(value.expires_at).toISOString() !== value.expires_at) {
    throw new Error("malformed_response");
  }
  return { authenticated: true, csrf: value.csrf_token, expires_at: value.expires_at };
}
function responseError(response, body) {
  if (response.status === 400) return new Error("invalid_request");
  if (body?.error === "scan_unavailable") return new Error("scan_unavailable");
  if (body?.error === "malformed_response") return new Error("malformed_response");
  return new Error("service_unavailable");
}
function resultIds(receipt) {
  if (typeof receipt !== "object" || receipt === null || !Array.isArray(receipt.scan_ids) ||
    receipt.scan_ids.length > SESSION_LIMITS.resultCount ||
    new Set(receipt.scan_ids).size !== receipt.scan_ids.length ||
    !receipt.scan_ids.every((id) => typeof id === "string" && /^[a-f0-9]{32}$/u.test(id))) {
    throw new Error("malformed_response");
  }
  return receipt.scan_ids;
}
export class SessionClient {
  constructor(fetcher = globalThis.fetch.bind(globalThis), options = {}) {
    this.fetcher = fetcher;
    this.timeoutMilliseconds = options.timeoutMilliseconds ?? SESSION_LIMITS.operationMilliseconds;
    this.epoch = 0; this.auth = null;
    this.operations = new Set(); this.handlers = { auth() {}, clear() {}, commit() {} };
  }
  connect(handlers) {
    this.handlers = { ...this.handlers, ...handlers };
    this.handlers.auth(this.auth === null ? "anonymous" : "authenticated");
  }
  begin(externalSignal) {
    this.epoch += 1;
    for (const prior of this.operations) prior.controller.abort(
      new DOMException("superseded", "AbortError"));
    this.operations.clear(); this.handlers.clear("operation");
    const controller = new AbortController();
    const scope = { controller, epoch: this.epoch, externalSignal, externalAbort: null, timer: null };
    scope.externalAbort = () => controller.abort(aborted(externalSignal));
    externalSignal?.addEventListener("abort", scope.externalAbort, { once: true });
    if (externalSignal?.aborted) scope.externalAbort();
    scope.timer = setTimeout(() => controller.abort(
      new DOMException("operation timeout", "AbortError")), this.timeoutMilliseconds);
    this.operations.add(scope);
    return scope;
  }
  finish(scope) {
    clearTimeout(scope.timer);
    scope.externalSignal?.removeEventListener("abort", scope.externalAbort);
    this.operations.delete(scope); }
  current(scope) {
    return this.operations.has(scope) && !scope.controller.signal.aborted &&
      scope.epoch === this.epoch; }
  invalidate(reason = "unauthorized", keep = null) {
    this.epoch += 1; this.auth = null; this.handlers.clear(reason);
    for (const scope of this.operations) if (scope !== keep) {
      scope.controller.abort(new DOMException(reason, "AbortError"));
    }
    if (keep !== null) keep.epoch = this.epoch;
    this.handlers.auth("anonymous");
  }
  async request(scope, path, init = {}) {
    let response;
    try {
      response = await abortable(Promise.resolve().then(() => this.fetcher(path, {
        credentials: "same-origin", ...init, signal: scope.controller.signal,
      })), scope.controller.signal);
    } catch (error) {
      if (error?.name === "AbortError") throw error;
      throw new Error("service_unavailable");
    }
    if (!(response instanceof Response)) throw new Error("service_unavailable");
    if (response.status === 401 || response.status === 403) {
      this.invalidate("unauthorized", scope); throw new Error("unauthorized");
    }
    let body;
    try {
      body = await abortable(Promise.resolve().then(() => response.json()), scope.controller.signal);
    } catch (error) {
      if (error?.name === "AbortError") throw error;
      throw new Error("malformed_response");
    }
    if (!response.ok) throw responseError(response, body);
    return body;
  }
  transitionAuth(scope, value) {
    const session = parseSession(value);
    if (!this.current(scope)) throw new DOMException("stale operation", "AbortError");
    this.auth = session; this.handlers.auth("authenticated");
    return session; }
  async refresh(scope) {
    const body = await this.request(scope, "/api/session", {
      method: "GET", headers: { accept: "application/json" } });
    return this.transitionAuth(scope, body); }
  async run(signal, action) {
    const scope = this.begin(signal);
    try { return await action(scope); } finally { this.finish(scope); } }
  async initialize(options = {}) {
    try {
      return await this.run(options.signal, async (scope) => {
        await this.refresh(scope); return true; });
    } catch (error) {
      if (error?.name === "AbortError" && options.signal?.aborted) throw error;
      return false;
    }
  }
  login(credentials, options = {}) {
    if (!exact(credentials, ["username", "password"]) ||
      typeof credentials.username !== "string" || typeof credentials.password !== "string" ||
      credentials.username.length > 256 || credentials.password.length > 512) {
      return Promise.reject(new Error("invalid_arguments"));
    }
    return this.run(options.signal, async (scope) => {
      this.invalidate("login", scope);
      const body = await this.request(scope, "/api/login", {
        method: "POST", headers: { "content-type": "application/json" },
        body: JSON.stringify(credentials) });
      return this.transitionAuth(scope, body);
    });
  }
  logout(options = {}) {
    return this.run(options.signal, async (scope) => {
      const csrf = this.auth?.csrf; this.invalidate("logout", scope);
      if (csrf === undefined) throw new Error("unauthorized");
      try {
        const body = await this.request(scope, "/api/logout", {
          method: "POST", headers: { "content-type": "application/json",
            "x-watchdog-csrf": csrf }, body: "{}" });
        if (!exact(body, ["authenticated"]) || body.authenticated !== false) {
          throw new Error("malformed_response"); }
      } finally { if (this.current(scope)) this.invalidate("logout", scope); }
    });
  }
  async loadResult(scope, id) {
    const envelope = await this.request(scope, `/api/results/${id}`, {
      method: "GET", headers: { accept: "application/json" } });
    if (!exact(envelope, ["result", "status"]) || envelope.status !== "ok" ||
      typeof envelope.result !== "object" || envelope.result === null ||
      envelope.result.scan_id !== id) throw new Error("malformed_response");
    return envelope;
  }
  commit(scope, output) {
    if (!this.current(scope) || this.auth === null) {
      throw new DOMException("stale operation", "AbortError"); }
    const value = clone(output);
    this.handlers.commit(value); return value;
  }
  executeScan(path, payload, kind, options = {}) {
    return this.run(options.signal, async (scope) => {
      await this.refresh(scope);
      if (options.consent !== true) throw new Error("provider_consent_required");
      const receipt = await this.request(scope, path, {
        method: "POST", headers: { accept: "application/json",
          "content-type": "application/json", "x-watchdog-csrf": this.auth.csrf },
        body: JSON.stringify(payload) });
      const ids = resultIds(receipt);
      let output;
      if (kind === "live_page") {
        const exchange = await decodeLiveExchange({ request: payload, receipt,
          loadResult: (id) => this.loadResult(scope, id) });
        output = presentExchange(exchange);
      } else {
        if (receipt.mode !== kind) throw new Error("malformed_response");
        const envelopes = await Promise.all(ids.map((id) => this.loadResult(scope, id)));
        output = { mode: kind, receipt: clone(receipt),
          results: envelopes.map(({ result }) => clone(result)) };
      }
      await this.refresh(scope); return this.commit(scope, output);
    });
  }
  scanPaste(payload, options) {
    const kind = payload?.mode === "url" ? "paste_url" : "paste_html";
    return this.executeScan("/api/scans/paste", payload, kind, options); }
  scanLive(payload, options) {
    return this.executeScan("/api/scans/live", payload, "live_page", options); }
  getResult(id, options = {}) {
    if (typeof id !== "string" || !/^[a-f0-9]{32}$/u.test(id)) {
      return Promise.reject(new Error("invalid_arguments")); }
    return this.run(options.signal, async (scope) => {
      await this.refresh(scope);
      const { result } = await this.loadResult(scope, id);
      await this.refresh(scope);
      return this.commit(scope, { mode: result.mode, results: [clone(result)] });
    });
  }
}
const clients = new WeakMap();
export function sessionClientFor(owner, fetcher = globalThis.fetch.bind(globalThis), options = {}) {
  if (!clients.has(owner)) clients.set(owner, new SessionClient(fetcher, options));
  return clients.get(owner); }
