import assert from "node:assert/strict";
import test from "node:test";

import worker from "../dist/worker/index.js";

test("the exported Worker entrypoint serves health without secrets", async () => {
  const response = await worker.fetch(new Request("https://example.test/api/health"), {});
  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), { status: "ok", service: "watch-dog" });
});

test("the real entrypoint fails closed for unimplemented API routes", async () => {
  const response = await worker.fetch(new Request("https://example.test/api/scans", { method: "POST" }), {});
  assert.equal(response.status, 503);
  assert.deepEqual(await response.json(), { error: "not_configured" });
});

test("the real entrypoint delegates public requests to the asset binding", async () => {
  const response = await worker.fetch(new Request("https://example.test/"), {
    ASSETS: { fetch: async () => new Response("asset") },
  });
  assert.equal(await response.text(), "asset");
});
