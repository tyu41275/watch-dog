import { renderResults } from "./results.js";
import { sessionClientFor } from "./session-client.js";
const status = document.querySelector("#app-status"); const results = document.querySelector("#results");
const loginPanel = document.querySelector("#login-panel"); const scanPanel = document.querySelector("#scan-panel");
const client = sessionClientFor(document); const setStatus = (message, kind = "ok") => {
  if (status) { status.textContent = message; status.dataset.kind = kind; } };
client.connect({
  commit(displays) { renderResults(results, displays); setStatus(`Rendered ${displays.length} bounded result${displays.length === 1 ? "" : "s"}.`); },
  invalidate() { if (results) results.hidden = true; },
  auth(state) { if (!loginPanel || !scanPanel) return;
    loginPanel.hidden = state === "authenticated"; scanPanel.hidden = state !== "authenticated"; },
});
const consent = () => document.querySelector("#provider-consent")?.checked === true;
async function busy(control, action) {
  if (control) control.disabled = true;
  try { await action(); } catch (error) { setStatus(error?.message ?? "service_unavailable", "error"); }
  finally { if (control) control.disabled = false; } }
const loginForm = document.querySelector("#login-form");
loginForm?.addEventListener("submit", (event) => {
  event.preventDefault(); const button = loginForm.querySelector("button[type='submit']");
  void busy(button, async () => { const data = new FormData(loginForm);
    await client.login({ username: data.get("username"), password: data.get("password") });
    loginForm.reset(); setStatus("Signed in. Scans remain ephemeral and session-owned."); });
});
document.querySelector("#logout")?.addEventListener("click", (event) => void busy(event.currentTarget,
  async () => { await client.logout(); setStatus("Signed out."); }));
for (const [selector, payload] of [
  ["#url-form", (data) => ({ mode: "url", url: data.get("url") })],
  ["#html-form", (data) => ({ mode: "html", html: data.get("html"), base_url: data.get("base_url") })],
]) {
  const form = document.querySelector(selector);
  form?.addEventListener("submit", (event) => {
    event.preventDefault(); const button = form.querySelector("button[type='submit']");
    void busy(button, async () => { setStatus("Analyzing through the shared pipeline…");
      await client.scanPaste(payload(new FormData(form)), { consent: consent() });
    });
  });
}
document.querySelector("#inspect-page")?.addEventListener("click", (event) => void busy(event.currentTarget, async () => {
    setStatus("Enumerating the current rendered anchors…");
    const { inspectCurrentPage } = await import("./webmcp.js");
    await inspectCurrentPage(document, { consent: consent() }); }));
if (loginPanel) void client.initialize().then((authenticated) => setStatus(authenticated
  ? "Signed in. Scans remain ephemeral and session-owned." : "Sign in to begin."));
