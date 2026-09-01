import { decodeReceipt, decodeResult, decodeSession } from "./protocol.js";
const abortError = (s) => s.reason instanceof Error ? s.reason : new DOMException("aborted", "AbortError");
function abortable(promise, signal) { signal.throwIfAborted(); return new Promise((resolve, reject) => {
  let done = false; const finish = (fn, value) => { if (done) return; done = true; signal.removeEventListener("abort", abort); fn(value); };
  const abort = () => finish(reject, abortError(signal)); signal.addEventListener("abort", abort, { once: true });
  Promise.resolve(promise).then((value) => finish(resolve, value), (error) => finish(reject, error)); }); }
function responseError(response, body) { if ([401, 403].includes(response.status)) return new Error("unauthorized"); if (response.status === 400) return new Error("invalid_request");
  return new Error(["scan_unavailable", "malformed_response"].includes(body?.error) ? body.error : "service_unavailable"); }
export class SessionClient {
  constructor(fetcher = globalThis.fetch.bind(globalThis)) { this.fetcher = fetcher; this.state = "anonymous"; this.csrf = null; this.epoch = 0; this.sequence = 0; this.logoutPending = false; this.operations = new Set(); this.handlers = { commit() {}, invalidate() {}, auth() {} }; }
  connect(handlers) { this.handlers = { ...this.handlers, ...handlers }; this.handlers.auth(this.state); }
  invalidate(reason = "unauthorized") { this.epoch += 1; this.state = "invalidating"; this.csrf = null; this.handlers.invalidate(reason); for (const operation of this.operations) operation.abort(); this.operations.clear(); this.state = "anonymous"; this.handlers.auth(this.state); }
  begin(external) { this.handlers.invalidate("operation"); for (const operation of this.operations) operation.abort(); this.operations.clear(); const operation = new AbortController();
    const sequence = ++this.sequence; const abort = () => operation.abort(abortError(external)); external?.addEventListener("abort", abort, { once: true });
    if (external?.aborted) abort(); this.operations.add(operation); return { operation, sequence, finish: () => { external?.removeEventListener("abort", abort); this.operations.delete(operation); } }; }
  async request(path, init, signal) { let response; try { response = await abortable(this.fetcher(path, { credentials: "same-origin", ...init, signal }), signal); } catch (error) { if (error?.name === "AbortError") throw error; throw new Error("service_unavailable"); } if (!(response instanceof Response)) throw new Error("service_unavailable");
    if ([401, 403].includes(response.status)) { this.invalidate(); throw new Error("unauthorized"); } let body;
    try { body = await abortable(response.json(), signal); } catch (error) { if (error?.name === "AbortError") throw error; throw new Error("malformed_response"); } if (!response.ok) throw responseError(response, body); return body; }
  async refresh(signal) { try { const session = decodeSession(await this.request("/api/session", { method: "GET", headers: { accept: "application/json" } }, signal)); this.csrf = session.csrf; this.state = "authenticated"; this.handlers.auth(this.state); return session; }
    catch (error) { if (error?.name !== "AbortError") this.invalidate(error.message); throw error; } }
  async initialize() { const scope = new AbortController(); try { await this.refresh(scope.signal); return true; } catch { return false; } }
  async login(credentials) { this.invalidate("login"); const scope = new AbortController(); const body = await this.request("/api/login", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(credentials) }, scope.signal); const session = decodeSession(body);
    this.epoch += 1; this.csrf = session.csrf; this.state = "authenticated"; this.handlers.auth(this.state); return session; }
  async logout() { const csrf = this.csrf; this.logoutPending = true; this.invalidate("logout"); const scope = new AbortController(); try { const body = await this.request("/api/logout",
    { method: "POST", headers: { "content-type": "application/json", "x-watchdog-csrf": csrf ?? "" }, body: "{}" }, scope.signal);
    if (!body || Object.keys(body).join() !== "authenticated" || body.authenticated !== false) throw new Error("malformed_response"); } finally { this.invalidate("logout"); this.logoutPending = false; } }
  async result(id, descriptor, signal) { return decodeResult({ scanId: id, ...descriptor }, await this.request(`/api/results/${id}`, { method: "GET", headers: { accept: "application/json" } }, signal)); }
  async execute(descriptor, path, payload, { consent = false, signal } = {}) { if (this.logoutPending) throw new Error("unauthorized");
    if (!consent && path !== null) throw new Error("provider_consent_required");
    const active = this.begin(signal); const operation = active.operation; let epoch; try { await this.refresh(operation.signal); epoch = this.epoch; let displays;
      if (path === null) displays = [await this.result(descriptor.scanId, {}, operation.signal)]; else { const receipt = decodeReceipt(descriptor,
        await this.request(path, { method: "POST", headers: { accept: "application/json", "content-type": "application/json",
          "x-watchdog-csrf": this.csrf, "x-watchdog-provider-consent": "google_safe_browsing" }, body: JSON.stringify(payload) }, operation.signal));
        displays = await Promise.all(receipt.scanIds.map((id, resultIndex) => this.result(id, { receipt, resultIndex }, operation.signal))); }
      await this.refresh(operation.signal); if (epoch !== this.epoch || active.sequence !== this.sequence || this.state !== "authenticated" || this.logoutPending)
        throw new DOMException("stale operation", "AbortError"); this.handlers.commit(displays); return { mode: descriptor.kind, results: displays };
    } finally { active.finish(); } }
  scanPaste(payload, options) { const kind = payload.mode === "url" ? "paste_url" : "paste_html";
    return this.execute(kind === "paste_url" ? { kind, requestedUrl: payload.url } : { kind }, "/api/scans/paste", payload, options); }
  scanLive(payload, options) { return this.execute({ kind: "live_page", observedCandidates: payload.candidates.length + payload.extraction_rejections.length }, "/api/scans/live", payload, options); }
  getResult(id, options) { return this.execute({ kind: "result", scanId: id }, null, null, options); }
}
const clients = new WeakMap();
export function sessionClientFor(pageDocument, fetcher = globalThis.fetch.bind(globalThis)) { if (!clients.has(pageDocument)) clients.set(pageDocument, new SessionClient(fetcher)); return clients.get(pageDocument); }
