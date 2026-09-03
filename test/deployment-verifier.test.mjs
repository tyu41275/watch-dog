import assert from "node:assert/strict";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawn } from "node:child_process";
import test from "node:test";

test("deployment verifier exercises all gates and preserves only sanitized evidence", async () => {
  const directory = await mkdtemp(join(tmpdir(), "watch-dog-verifier-"));
  const evidencePath = join(directory, "evidence.json");
  const username = "u".repeat(8);
  const password = "p".repeat(24);
  try {
    const child = spawn(process.execPath, [
      "--import", "./test/support/deployment-verifier-mock.mjs",
      "./scripts/verify-deployment.mjs",
    ], {
      env: {
        ...process.env,
        DEPLOYED_URL: "https://unit.workers.dev/",
        EXPECTED_SHA: "a".repeat(40),
        WATCH_DOG_JUDGE_USERNAME: username,
        WATCH_DOG_JUDGE_PASSWORD: password,
        WATCH_DOG_PROVIDER_CONSENT: "true",
        DEPLOYMENT_ID_REDACTED: "abcd1234…ef12",
        EVIDENCE_PATH: evidencePath,
      },
      stdio: ["ignore", "pipe", "pipe"],
    });
    const output = [];
    child.stdout.on("data", (chunk) => output.push(chunk));
    child.stderr.on("data", (chunk) => output.push(chunk));
    const [code] = await new Promise((resolve) => child.once("close", (...args) => resolve(args)));
    assert.equal(code, 0, Buffer.concat(output).toString("utf8"));
    assert.match(Buffer.concat(output).toString("utf8"), /LIVE_VERIFICATION_PASS/u);
    const raw = await readFile(evidencePath, "utf8");
    const evidence = JSON.parse(raw);
    assert.equal(evidence.deployment.revision, "a".repeat(40));
    assert.equal(evidence.cookie.max_age_seconds, 900);
    assert.equal(evidence.provider.state, "no_match");
    assert.deepEqual(Object.keys(evidence.network.refusal_reasons).sort(),
      ["loopback", "private", "rebinding_style", "redirect_to_disallowed"]);
    for (const forbidden of [username, password, "token-1", "token-2", "1".repeat(32)]) {
      assert.equal(raw.includes(forbidden), false);
    }
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
