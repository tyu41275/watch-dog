import base from "./playwright.config.mjs";

const recordingId = process.env.WATCHDOG_RECORDING_ID ??
  new Date().toISOString().replaceAll(/[:.]/gu, "-");
if (!/^[A-Za-z0-9._-]+$/u.test(recordingId)) throw new Error("invalid recording id");

export default {
  ...base,
  testMatch: "recording.spec.mjs",
  retries: 0,
  preserveOutput: "always",
  outputDir: `artifacts/operator-recording/${recordingId}`,
  use: { ...base.use, headless: false, trace: "off", screenshot: "off", video: "on" },
};
