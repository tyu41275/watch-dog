import { sessionClientFor } from "./session-client.js";
import { extractRenderedPage } from "./webmcp.js";

const client = sessionClientFor(document);
const status = document.querySelector("#app-status");
const output = document.querySelector("#results");
const loginPanel = document.querySelector("#login-panel");
const scanPanel = document.querySelector("#scan-panel");

function setStatus(message, kind = "status") {
  if (status !== null) {
    status.textContent = message;
    status.dataset.kind = kind;
  }
}

client.connect({
  auth(state) {
    if (loginPanel !== null) loginPanel.hidden = state === "authenticated";
    if (scanPanel !== null) scanPanel.hidden = state !== "authenticated";
  },
  clear() {
    if (output !== null) {
      output.textContent = "";
      output.hidden = true;
    }
  },
  commit(value) {
    if (output !== null) {
      output.textContent = JSON.stringify(value, null, 2);
      output.hidden = false;
    }
    setStatus("Canonical session-owned results committed.");
  },
});

async function busy(control, action) {
  if (control !== null) control.disabled = true;
  try {
    await action();
  } catch (error) {
    if (error?.name !== "AbortError") setStatus(error?.message ?? "service_unavailable", "error");
  } finally {
    if (control !== null) control.disabled = false;
  }
}

const consent = () => document.querySelector("#provider-consent")?.checked === true;
const loginForm = document.querySelector("#login-form");
loginForm?.addEventListener("submit", (event) => {
  event.preventDefault();
  const button = loginForm.querySelector("button[type='submit']");
  void busy(button, async () => {
    const data = new FormData(loginForm);
    await client.login({ username: data.get("username"), password: data.get("password") });
    loginForm.reset();
    setStatus("Signed in. Scans remain ephemeral and session-owned.");
  });
});

document.querySelector("#logout")?.addEventListener("click", (event) => {
  void busy(event.currentTarget, async () => {
    await client.logout();
    setStatus("Signed out.");
  });
});

for (const [selector, payload] of [
  ["#url-form", (data) => ({ mode: "url", url: data.get("url") })],
  ["#html-form", (data) => ({ mode: "html", html: data.get("html"),
    base_url: data.get("base_url") })],
]) {
  const form = document.querySelector(selector);
  form?.addEventListener("submit", (event) => {
    event.preventDefault();
    const button = form.querySelector("button[type='submit']");
    void busy(button, async () => {
      setStatus("Analyzing through the shared pipeline…");
      await client.scanPaste(payload(new FormData(form)), { consent: consent() });
    });
  });
}

const resultForm = document.querySelector("#result-form");
resultForm?.addEventListener("submit", (event) => {
  event.preventDefault();
  const button = resultForm.querySelector("button[type='submit']");
  void busy(button, async () => {
    const data = new FormData(resultForm);
    await client.getResult(data.get("scan_id"));
  });
});

document.querySelector("#inspect-page")?.addEventListener("click", (event) => {
  void busy(event.currentTarget, async () => {
    const observedAt = new Date().toISOString();
    setStatus("Enumerating the current rendered anchors…");
    await client.scanLive({ document_url: document.URL, observed_at: observedAt,
      ...extractRenderedPage(document, observedAt) }, { consent: consent() });
  });
});

if (loginPanel !== null) {
  void client.initialize().then((authenticated) => setStatus(authenticated
    ? "Signed in. Scans remain ephemeral and session-owned." : "Sign in to begin."));
}
