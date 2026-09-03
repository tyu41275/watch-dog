import { defineConfig } from "@playwright/test";
import { chromiumControls } from "./playwright.config.mjs";
export default defineConfig({
  testDir: "./e2e", testMatch: "recording.spec.mjs",
  workers: 1, retries: 0, timeout: 60_000,
  outputDir: "recordings/operator",
  use: {
    browserName: "chromium", headless: false, ignoreHTTPSErrors: true,
    baseURL: "https://watch.example", video: "on", trace: "on",
    launchOptions: { args: chromiumControls },
  },
});
