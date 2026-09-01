import { renderResults, validResultEnvelope } from "/results.js";
import { validScanReceipt, validSession } from "/webmcp.js";
const status = document.querySelector("#app-status"); const results = document.querySelector("#results");
let csrf = null; let sessionGeneration = 0;
function setStatus(message, kind = "ok") { if (status) { status.textContent = message; status.dataset.kind = kind; } }
async function request(path, init = {}) {
  let response;
  try { response = await fetch(path, { credentials: "same-origin", ...init }); }
  catch { throw new Error("service_unavailable"); }
  let body = null;
  try { body = await response.json(); } catch { throw new Error("malformed_response"); }
  if (!response.ok) throw new Error(typeof body?.error === "string" ? body.error : "service_unavailable");
  return body;
}
async function session() {
  const body = await request("/api/session");
  if (!validSession(body)) throw new Error("malformed_response");
  csrf = body.csrf_token;
  return body;
}
async function showReceipt(receipt, expectedUrl) {
  const generation = sessionGeneration;
  results.hidden = true;
  if (!validScanReceipt(receipt, expectedUrl)) throw new Error("malformed_response");
  const records = await Promise.all(receipt.scan_ids.map(async (scanId) => {
    const body = await request(`/api/results/${scanId}`);
    if (!validResultEnvelope(body, scanId)) throw new Error("malformed_response");
    return body.result;
  }));
  try { await session(); } catch (error) { results.hidden = true; throw error; }
  if (generation !== sessionGeneration || scanPanel?.hidden === true) return;
  renderResults(results, records);
  setStatus(`Rendered ${records.length} bounded result${records.length === 1 ? "" : "s"}.`);
}
async function mutation(path, body, providerConsent = false) {
  if (csrf === null) await session();
  return request(path, {
    method: "POST",
    headers: { "content-type": "application/json", "x-watchdog-csrf": csrf,
      ...(providerConsent ? { "x-watchdog-provider-consent": "google_safe_browsing" } : {}) },
    body: JSON.stringify(body),
  });
}
async function busy(form, action) {
  const button = form.querySelector("button[type='submit']");
  if (button) button.disabled = true;
  try { await action(); } catch (error) { results.hidden = true;
    setStatus(error?.message || "service_unavailable", "error"); }
  finally { if (button) button.disabled = false; }
}
const loginPanel = document.querySelector("#login-panel"); const scanPanel = document.querySelector("#scan-panel");
const loginForm = document.querySelector("#login-form");
loginForm?.addEventListener("submit", (event) => {
  event.preventDefault();
  void busy(loginForm, async () => {
    const data = new FormData(loginForm);
    const body = await request("/api/login", {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ username: data.get("username"), password: data.get("password") }),
    });
    if (!validSession(body)) throw new Error("malformed_response");
    csrf = body.csrf_token; loginForm.reset();
    loginPanel.hidden = true; scanPanel.hidden = false;
    setStatus("Signed in. Scans remain ephemeral and session-owned.");
  });
});
document.querySelector("#logout")?.addEventListener("click", () => void (async () => {
  sessionGeneration += 1;
  try {
    await mutation("/api/logout", {});
    csrf = null; scanPanel.hidden = true; loginPanel.hidden = false; results.hidden = true;
    setStatus("Signed out.");
  } catch (error) { setStatus(error?.message || "service_unavailable", "error"); }
})());
for (const [selector, makeBody] of [
  ["#url-form", (data) => ({ mode: "url", url: data.get("url") })],
  ["#html-form", (data) => ({ mode: "html", html: data.get("html"), base_url: data.get("base_url") })],
]) {
  const form = document.querySelector(selector);
  form?.addEventListener("submit", (event) => {
    event.preventDefault();
    void busy(form, async () => {
      if (document.querySelector("#provider-consent")?.checked !== true)
        throw new Error("provider_consent_required");
      setStatus("Analyzing through the shared pipeline…");
      const payload = makeBody(new FormData(form));
      await showReceipt(await mutation("/api/scans/paste", payload, true), payload.mode === "url" ? payload.url : undefined);
    });
  });
}
document.querySelector("#inspect-page")?.addEventListener("click", (event) => void (async () => {
  const button = event.currentTarget; button.disabled = true;
  try {
    if (document.querySelector("#provider-consent")?.checked !== true)
      throw new Error("provider_consent_required");
    setStatus("Enumerating the current rendered anchors…");
    const { inspectCurrentPage } = await import("/webmcp.js");
    await showReceipt(JSON.parse(await inspectCurrentPage({
      pageDocument: document, fetcher: globalThis.fetch.bind(globalThis), providerConsent: true,
    })));
  } catch (error) { results.hidden = true; setStatus(error?.message || "service_unavailable", "error"); }
  finally { button.disabled = false; }
})());
document.addEventListener("watchdog:scan-receipt", (event) => {
  void showReceipt(event.detail).catch((error) =>
    setStatus(error?.message || "service_unavailable", "error"));
});
document.addEventListener("watchdog:scan-result", (event) => {
  const generation = sessionGeneration;
  results.hidden = true;
  void session().then(() => { if (generation !== sessionGeneration || scanPanel?.hidden === true) return;
    renderResults(results, [event.detail]); setStatus("Rendered 1 bounded result."); })
    .catch((error) => { results.hidden = true; setStatus(error?.message || "service_unavailable", "error"); });
});
if (loginPanel) {
  void session().then(() => {
    loginPanel.hidden = true; scanPanel.hidden = false;
    setStatus("Signed in. Scans remain ephemeral and session-owned.");
  }).catch(() => {
    loginPanel.hidden = false; scanPanel.hidden = true;
    setStatus("Sign in to begin.");
  });
}
