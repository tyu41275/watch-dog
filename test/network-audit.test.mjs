import assert from "node:assert/strict"; import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import path from "node:path"; import { tmpdir } from "node:os";
import test from "node:test";
import { auditTrace } from "../e2e/network-audit.mjs";
test("trace audit covers batched datagrams and every spawned task", async () => {
  const directory = await mkdtemp(path.join(tmpdir(), "watchdog-trace-")); const summary = path.join(directory, "summary.json"); const census = path.join(directory, "census.jsonl");
  try {
    await writeFile(path.join(directory, "trace.9"), 'execve("/usr/bin/node", ["/usr/bin/node", "e2e/runtime-supervisor.mjs"], 0x0) = 0\nclone(child_stack=NULL, flags=SIGCHLD) = 10\n+++ exited with 0 +++\n'); await writeFile(path.join(directory, "trace.10"), 'sendmmsg(3, [{msg_hdr={msg_name={sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("192.0.2.1")}}}], 1, 0) = 1\n+++ exited with 0 +++\n');
    await writeFile(census, '{"pid":9,"ppid":1}\n'); await assert.rejects(auditTrace({ traceDirectory: directory, censusPath: census, summaryPath: summary })); assert.equal(JSON.parse(await readFile(summary)).successful_non_loopback[0].syscall, "datagram");
    await rm(path.join(directory, "trace.10"));
    await assert.rejects(auditTrace({ traceDirectory: directory, censusPath: census, summaryPath: summary }));
    assert.deepEqual(JSON.parse(await readFile(summary)).missing_trace_pids, ["10"]);
  } finally { await rm(directory, { recursive: true, force: true }); }
});
