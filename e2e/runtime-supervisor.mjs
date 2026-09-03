import { execFileSync, spawn } from "node:child_process";
import { closeSync, copyFileSync, openSync, readdirSync, readFileSync, readlinkSync, statSync, symlinkSync } from "node:fs";
import { appendFile, mkdir, writeFile } from "node:fs/promises";
import https from "node:https";
import net from "node:net";
import path from "node:path";
import crypto from "node:crypto";
import { auditTrace } from "./network-audit.mjs";
const output = "/out"; const state = "/state";
const children = new Set(); let stopping = false;
function launch(command, args, name, env = {}) {
  const log = openSync(path.join(output, `${name}.log`), "a");
  const child = spawn(command, args, { cwd: env.WD_CWD, env: { ...process.env, ...env }, stdio: ["ignore", log, log],
    detached: false });
  closeSync(log); children.add(child); child.once("exit", () => { children.delete(child); });
  return child;
}
async function stop(child) {
  if (child.exitCode !== null || child.signalCode !== null) return;
  child.kill("SIGTERM");
  await Promise.race([new Promise((resolve) => child.once("exit", resolve)),
    new Promise((resolve) => setTimeout(resolve, 5_000))]);
  if (child.exitCode === null && child.signalCode === null) child.kill("SIGKILL");
}
async function stopAll() {
  if (stopping) return; stopping = true;
  await Promise.all([...children].map(stop));
}
function httpsGet(route) {
  return new Promise((resolve, reject) => {
    const request = https.get({ host: "127.0.0.1", port: 8787, path: route,
      servername: "watch.example", headers: { host: "watch.example" }, rejectUnauthorized: false },
    (response) => { response.resume(); response.once("end", () => resolve(response.statusCode)); });
    request.once("error", reject); request.setTimeout(1_000, () => request.destroy());
  });
}
async function ready() {
  const until = Date.now() + 30_000;
  while (Date.now() < until) {
    try { if (await httpsGet("/api/health") === 200) return; } catch {}
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  throw new Error("wrangler readiness timeout");
}
async function census(stage) {
  for (const entry of readdirSync("/proc").filter((value) => /^\d+$/u.test(value))) {
    try {
      const stat = readFileSync(`/proc/${entry}/stat`, "utf8");
      await appendFile(path.join(output, "process-census.jsonl"), `${JSON.stringify({ stage,
        pid: Number(entry), ppid: Number(stat.slice(stat.lastIndexOf(")") + 2).split(" ")[1]),
        exe: readlinkSync(`/proc/${entry}/exe`) })}\n`);
    } catch {}
  }
}
function rejectedConnectProbe() {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection({ host: "127.0.0.1", port: 9323 }); let data = "";
    socket.setEncoding("ascii"); socket.once("connect", () => socket.write(
      "CONNECT blocked.example.invalid:443 HTTP/1.1\r\n\r\n"));
    socket.on("data", (chunk) => { data += chunk; });
    socket.once("end", () => data.startsWith("HTTP/1.1 403") ? resolve() : reject(
      new Error("connector rejection failed"))); socket.once("error", reject);
  });
}
function collectAttachments(value, found = []) {
  if (Array.isArray(value)) for (const item of value) collectAttachments(item, found);
  else if (value !== null && typeof value === "object") {
    if (Array.isArray(value.attachments)) found.push(...value.attachments);
    for (const child of Object.values(value)) collectAttachments(child, found);
  }
  return found;
}
process.once("SIGTERM", () => { void stopAll().finally(() => process.exit(143)); });
process.once("SIGINT", () => { void stopAll().finally(() => process.exit(130)); });
let result = "FAIL";
try {
  await Promise.all(["home", "config", "cache", "data", "wrangler", "work"].map((name) =>
    mkdir(path.join(state, name), { recursive: true })));
  copyFileSync("/work/wrangler.jsonc", path.join(state, "work/wrangler.jsonc")); for (const name of ["src", "public", "node_modules", "package.json", "tsconfig.json"]) symlinkSync(path.join("/work", name), path.join(state, "work", name));
  const key = path.join(state, "key.pem"); const cert = path.join(state, "cert.pem");
  execFileSync("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
    "-subj", "/CN=watch.example", "-addext", "subjectAltName=DNS:watch.example",
    "-keyout", key, "-out", cert], { stdio: "ignore" });
  const user = `judge-${crypto.randomBytes(8).toString("hex")}`;
  const password = crypto.randomBytes(24).toString("base64url");
  const signing = crypto.randomBytes(32).toString("base64url");
  const wrangler = launch(process.execPath, [path.resolve("node_modules/wrangler/bin/wrangler.js"), "dev", "--config", path.join(state, "work/wrangler.jsonc"),
    "--local", "--ip", "127.0.0.1", "--port", "8787", "--local-protocol", "https",
    "--https-key-path", key, "--https-cert-path", cert, "--persist-to", path.join(state, "wrangler"),
    "--var", `ADMIN_USERNAME:${user}`, "--var", `ADMIN_PASSWORD:${password}`,
    "--var", `SESSION_SIGNING_KEY:${signing}`, "--var", "GOOGLE_SAFE_BROWSING_ENABLED:false",
    "--log-level", "error", "--show-interactive-dev-session=false"], "wrangler", { WD_CWD: path.join(state, "work") });
  const connector = launch(process.execPath, ["e2e/connect-tunnel.mjs"], "connector",
    { WD_CONNECT_SUMMARY: path.join(output, "connect-summary.json") });
  await ready(); await rejectedConnectProbe(); await census("ready");
  const cli = path.resolve("node_modules/@playwright/test/cli.js");
  const tests = launch(process.execPath, [cli, "test", "--config=playwright.config.mjs"],
    "playwright", { WD_USER: user, WD_PASS: password,
      WD_TEST_OUTPUT: "/out/playwright", WD_JSON_REPORT: "/out/playwright-results.json" });
  const testCode = await new Promise((resolve) => tests.once("exit", resolve));
  if (testCode !== 0) throw new Error(`browser acceptance exited ${testCode}`);
  if (readdirSync("/out/playwright", { recursive: true, withFileTypes: true }).some((entry) =>
    entry.isFile() && /\.(?:png|webm|zip)$/u.test(entry.name)))
    throw new Error("passing run retained browser artifacts");
  const controlled = launch(process.execPath, [cli, "test", "--config=playwright.config.mjs"],
    "controlled-artifact", { WD_CONTROLLED_FAILURE: "1", WD_TEST_OUTPUT: "/out/controlled",
      WD_JSON_REPORT: "/out/controlled-results.json" });
  const controlledCode = await new Promise((resolve) => controlled.once("exit", resolve));
  if (controlledCode === 0) throw new Error("controlled artifact probe unexpectedly passed");
  const artifactFiles = readdirSync("/out/controlled", { recursive: true, withFileTypes: true })
    .filter((entry) => entry.isFile()).map((entry) => path.join(entry.parentPath, entry.name));
  const requiredSuffixes = [".png", ".webm", ".zip", "error-context.md"];
  const controlledReport = JSON.parse(readFileSync("/out/controlled-results.json"));
  const attachments = collectAttachments(controlledReport);
  const requiredTypes = ["image/png", "video/webm", "application/zip", "text/markdown"];
  if (requiredSuffixes.some((suffix) => !artifactFiles.some((file) => file.endsWith(suffix))) ||
    artifactFiles.some((file) => !file.startsWith("/out/controlled/") ||
      statSync(file).size <= 0 || statSync(file).size > 20e6) ||
    controlledReport.stats?.unexpected !== 1 || controlledReport.stats?.expected !== 0 ||
    requiredTypes.some((type) => !attachments.some(({ contentType }) => contentType === type)) ||
    attachments.some(({ path: file }) => typeof file !== "string" ||
      !file.startsWith("/out/controlled/") || !artifactFiles.includes(file))) {
    throw new Error("controlled artifacts are missing or unbounded");
  }
  await census("post-tests");
  for (let elapsed = 0; elapsed < 30_000; elapsed += 5_000) {
    await new Promise((resolve) => setTimeout(resolve, 5_000)); await census(`hold-${elapsed + 5_000}`);
  }
  await stop(connector); await stop(wrangler); await census("services-stopped"); await new Promise((resolve) => setTimeout(resolve, 1_000));
  const report = await auditTrace({ traceDirectory: path.join(output, "raw-trace"),
    censusPath: path.join(output, "process-census.jsonl"),
    summaryPath: path.join(output, "network-audit.json"), ignoredPids: readdirSync("/proc/self/task").map(Number) });
  if (report.verdict !== "PASS" || report.endpoints.some(({ port }) => port === 9444)) throw new Error("trace verdict failed");
  const connectorSummary = JSON.parse(readFileSync(path.join(output, "connect-summary.json")));
  if (connectorSummary.rejected_authorities < 1 ||
    connectorSummary.backend_dials !== connectorSummary.accepted_authorities ||
    connectorSummary.upstream_host !== "127.0.0.1" || connectorSummary.upstream_port !== 8787 ||
    connectorSummary.backend_failures !== 0 || connectorSummary.retained_payload_bytes !== 0) {
    throw new Error("connector summary failed");
  }
  result = "PASS";
} finally {
  await stopAll();
  await writeFile(path.join(output, "runtime-result.json"), `${JSON.stringify({ result,
    supervisor_pid: process.pid, completed_at: new Date().toISOString() })}\n`);
}
if (result !== "PASS") process.exitCode = 1;
