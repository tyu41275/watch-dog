import assert from "node:assert/strict";
import test from "node:test";

import {
  createSupportingTools,
  getScanResult,
  scanUrl,
} from "../public/webmcp.js";

const session = () => Response.json({
  authenticated: true,
  csrf_token: "c".repeat(32),
  expires_at: "2026-09-01T13:00:00.000Z",
});

const receipt = (mode = "paste_url") => Response.json({
  mode,
  scan_ids: ["a".repeat(32)],
  accepted_targets: 1,
  rejected_candidates: 0,
  truncated: false,
  unscannable_reason: null,
  fetch_evidence: null,
}, { status: 201 });

test("supporting tools have literal bounded read-only untrusted contracts", () => {
  const tools = createSupportingTools(async () => new Response());
  assert.deepEqual(tools.map(({ name }) => name), ["scan_url", "get_scan_result"]);
  for (const tool of tools) {
    assert.deepEqual(tool.annotations, { readOnlyHint: true, untrustedContentHint: true });
    assert.equal(tool.inputSchema.additionalProperties, false);
  }
  assert.deepEqual(tools[0].inputSchema.required, ["targetUrl"]);
  assert.equal(tools[0].inputSchema.properties.pastedHtml.maxLength, 200_000);
  assert.deepEqual(tools[1].inputSchema.required, ["scanId"]);
  assert.equal(tools[1].inputSchema.properties.scanId.pattern, "^[a-f0-9]{32}$");
  assert.throws(() => tools[0].execute({ targetUrl: "https://example.com", extra: true }),
    /invalid_arguments/);
  assert.throws(() => tools[1].execute({}), /invalid_arguments/);
});

test("scan_url uses authenticated URL and local-only HTML request shapes", async () => {
  for (const mode of ["url", "html"]) {
    const calls = [];
    const fetcher = async (path, init) => {
      calls.push({ path, init });
      return calls.length === 1 ? session() : receipt(`paste_${mode}`);
    };
    const output = JSON.parse(await scanUrl({
      fetcher,
      targetUrl: "https://example.com/base/",
      ...(mode === "html" ? { pastedHtml: "<a href='./one'>One</a>" } : {}),
    }));
    assert.equal(output.mode, `paste_${mode}`);
    assert.deepEqual(JSON.parse(calls[1].init.body), mode === "url"
      ? { mode: "url", url: "https://example.com/base/" }
      : { mode: "html", html: "<a href='./one'>One</a>", base_url: "https://example.com/base/" });
    assert.equal(calls[1].path, "/api/scans/paste");
    assert.equal(calls[1].init.headers["x-watchdog-csrf"], "c".repeat(32));
    assert.equal(calls[1].init.credentials, "same-origin");
  }
});

test("get_scan_result is session-owned, typed, bounded and cancellable", async () => {
  const scanId = "a".repeat(32);
  const output = JSON.parse(await getScanResult({
    scanId,
    fetcher: async (path, init) => {
      assert.equal(path, `/api/results/${scanId}`);
      assert.equal(init.credentials, "same-origin");
      return Response.json({ status: "ok", result: { scan_id: scanId, risk_label: "unknown" } });
    },
  }));
  assert.equal(output.scan_id, scanId);
  await assert.rejects(getScanResult({
    scanId,
    fetcher: async () => Response.json({ error: "missing" }, { status: 404 }),
  }), /service_unavailable/);
  await assert.rejects(getScanResult({
    scanId, fetcher: async () => Response.json({ status: "ok", result: { scan_id: "b".repeat(32) } }),
  }), /malformed_response/);
  await assert.rejects(getScanResult({ scanId: "raw-url", fetcher: async () => new Response() }),
    /invalid_arguments/);
  const controller = new AbortController();
  controller.abort();
  await assert.rejects(getScanResult({ scanId, fetcher: async () => new Response(), signal: controller.signal }),
    { name: "AbortError" });
});
