import { defineConfig } from "@playwright/test";

const port = 8787;
const channel = process.env.WATCHDOG_BROWSER_CHANNEL;
const baseURL = `https://127.0.0.1:${port}`;
const runId = process.env.WATCHDOG_EVIDENCE_ID ?? new Date().toISOString().replaceAll(/[:.]/gu, "-");

export default defineConfig({
  testDir: "./e2e",
  testIgnore: "**/recording.spec.mjs",
  fullyParallel: false,
  workers: 1,
  retries: 1,
  reporter: "line",
  outputDir: `test-results/playwright/${runId}`,
  use: {
    baseURL,
    browserName: "chromium",
    ...(channel ? { channel } : {}),
    ignoreHTTPSErrors: true,
    trace: "on-first-retry",
    screenshot: "only-on-failure",
    video: "retain-on-failure",
  },
  webServer: {
    command: `npx wrangler@4.127.1 dev --local --local-protocol https --port ${port} --var ADMIN_USERNAME:$WATCHDOG_TEST_USERNAME --var ADMIN_PASSWORD:$WATCHDOG_TEST_PASSWORD --var SESSION_SIGNING_KEY:$WATCHDOG_TEST_SIGNING_KEY`,
    url: `${baseURL}/api/health`,
    ignoreHTTPSErrors: true,
    reuseExistingServer: false,
    timeout: 120_000,
    env: {
      WATCHDOG_TEST_USERNAME: "playwright-judge",
      WATCHDOG_TEST_PASSWORD: "synthetic-browser-fixture",
      WATCHDOG_TEST_SIGNING_KEY: "playwright-signing-fixture-00001",
    },
  },
});
