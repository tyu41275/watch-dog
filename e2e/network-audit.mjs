import { readdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import net from "node:net";

const resultOk = (line) => / = (?:0|[1-9][0-9]*)$/u.test(line);
const endpointPatterns = [
  { family: "AF_INET", regex: /sin_port=htons\((\d+)\).*sin_addr=inet_addr\("([^"]+)"\)/u },
  { family: "AF_INET6", regex: /sin6_port=htons\((\d+)\).*inet_pton\(AF_INET6, "([^"]+)"/u },
];

function isLoopback(family, address) {
  if (family === "AF_INET") return net.isIP(address) === 4 && address.startsWith("127.");
  return net.isIP(address) === 6 && address === "::1";
}

function classifyLine(file, line, report) {
  for (const { family, regex } of endpointPatterns) {
    const match = regex.exec(line);
    if (match === null) continue;
    const endpoint = { file, family, port: Number(match[1]), address: match[2],
      syscall: line.includes("connect(") ? "connect" : line.includes("sendto(") ||
        line.includes("sendmsg(") ? "datagram" : "other", success: resultOk(line) };
    report.endpoints.push(endpoint);
    if (!isLoopback(family, endpoint.address)) {
      (endpoint.success ? report.successful_non_loopback : report.blocked_non_loopback).push(endpoint);
    }
    if ([53, 853, 5353].includes(endpoint.port)) {
      (endpoint.success ? report.successful_dns : report.blocked_dns).push(endpoint);
    }
  }
}

export async function auditTrace({ traceDirectory, censusPath, summaryPath,
  ignoredPids = [] }) {
  const ignored = new Set(ignoredPids.map(String));
  const files = (await readdir(traceDirectory)).filter((name) => /^trace\.\d+$/u.test(name));
  const traced = new Set(files.map((name) => name.split(".").at(-1)));
  const report = { trace_files: files.length, census_pids: [], endpoints: [],
    successful_non_loopback: [], blocked_non_loopback: [], successful_dns: [], blocked_dns: [],
    missing_trace_pids: [], incomplete_trace_pids: [], required_exec_classes: {}, verdict: "PASS" };
  const bodies = new Map();
  for (const file of files) {
    const body = await readFile(path.join(traceDirectory, file), "utf8"); bodies.set(file, body);
    for (const line of body.split("\n")) classifyLine(file, line, report);
    const pid = file.split(".").at(-1);
    if (!ignored.has(pid) && !/(?:exited with|killed by)/u.test(body)) report.incomplete_trace_pids.push(pid);
  }
  const census = (await readFile(censusPath, "utf8")).trim().split("\n").filter(Boolean)
    .map((line) => JSON.parse(line));
  report.census_pids = [...new Set(census.map(({ pid }) => String(pid)))].sort();
  report.missing_trace_pids = report.census_pids.filter((pid) => pid !== "1" &&
    !ignored.has(pid) && !traced.has(pid));
  const combined = [...bodies.values()].join("\n");
  for (const [name, expression] of Object.entries({
    wrangler: /wrangler/u, workerd: /workerd/u, connector: /connect-tunnel/u,
    playwright: /playwright/u, chromium: /chrome[^/]*\/chrome/u,
  })) report.required_exec_classes[name] = expression.test(combined);
  const missingClass = Object.values(report.required_exec_classes).some((value) => !value);
  if (report.successful_non_loopback.length || report.successful_dns.length ||
    report.missing_trace_pids.length || report.incomplete_trace_pids.length || missingClass) {
    report.verdict = "FAIL";
  }
  await writeFile(summaryPath, `${JSON.stringify(report, null, 2)}\n`);
  if (report.verdict !== "PASS") throw new Error("network trace acceptance failed");
  return report;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  await auditTrace({ traceDirectory: process.argv[2], censusPath: process.argv[3],
    summaryPath: process.argv[4], ignoredPids: process.argv.slice(5) });
}
