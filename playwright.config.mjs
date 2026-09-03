import { defineConfig } from "@playwright/test";

const evidenceId = process.env.WATCHDOG_EVIDENCE_ID ?? new Date().toISOString().replaceAll(/[:.]/gu, "-");
if (!/^[A-Za-z0-9._-]+$/u.test(evidenceId)) throw new Error("invalid evidence id");
const wrangler = "npx --yes wrangler@4.127.1 dev --ip 127.0.0.1 --port 8787 --local --local-protocol https --show-interactive-dev-session=false --var ADMIN_USERNAME:playwright-judge --var ADMIN_PASSWORD:synthetic-browser-fixture --var SESSION_SIGNING_KEY:playwright-signing-fixture-00001";

export default defineConfig({
  testDir: "./e2e",
  testMatch: "acceptance.spec.mjs",
  fullyParallel: false,
  workers: 1,
  retries: 0,
  timeout: 90_000,
  globalTimeout: 180_000,
  expect: { timeout: 10_000 },
  reporter: "line",
  preserveOutput: "failures-only",
  outputDir: `test-results/playwright/${evidenceId}`,
  use: {
    baseURL: "https://watch.example",
    browserName: "chromium",
    ignoreHTTPSErrors: true,
    proxy: { server: "http://127.0.0.1:9323" },
    launchOptions: { args: [
      "--disable-background-networking", "--disable-component-update", "--disable-sync",
      "--no-first-run", "--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1",
    ] },
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
    video: "retain-on-failure",
  },
  webServer: [
    {
      command: "node e2e/connect-tunnel.mjs",
      port: 9323,
      reuseExistingServer: false,
      timeout: 30_000,
      gracefulShutdown: { signal: "SIGTERM", timeout: 5_000 },
    },
    {
      command: wrangler,
      url: "https://127.0.0.1:8787/api/health",
      ignoreHTTPSErrors: true,
      reuseExistingServer: false,
      timeout: 120_000,
      gracefulShutdown: { signal: "SIGTERM", timeout: 10_000 },
      env: { XDG_CONFIG_HOME: `${process.cwd()}/.wrangler/xdg` },
    },
  ],
});
