import base from "./playwright.config.mjs";

const recordingId = process.env.WATCHDOG_RECORDING_ID ??
  new Date().toISOString().replaceAll(/[:.]/gu, "-");

export default {
  ...base,
  testIgnore: undefined,
  testMatch: "**/recording.spec.mjs",
  retries: 0,
  use: { ...base.use, headless: false, trace: "off", screenshot: "off", video: "on" },
  outputDir: `artifacts/operator-recording/${recordingId}`,
};
