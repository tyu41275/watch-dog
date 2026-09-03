import { defineConfig } from "@playwright/test";

export const chromiumControls = [
  "--proxy-server=http://127.0.0.1:9323",
  "--proxy-bypass-list=<-loopback>",
  "--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1",
  "--dns-prefetch-disable", "--disable-preconnect", "--disable-background-networking",
  "--disable-component-update", "--disable-component-extensions-with-background-pages",
  "--disable-default-apps", "--disable-domain-reliability", "--disable-sync",
  "--disable-pings", "--no-pings", "--disable-quic",
  "--disable-client-side-phishing-detection", "--disable-breakpad",
  "--metrics-recording-only", "--no-first-run", "--no-default-browser-check",
  "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
  "--disable-features=AutofillServerCommunication,CertificateTransparencyComponentUpdater,DnsOverHttps,DnsOverHttpsUpgrade,MediaRouter,NetworkTimeServiceQuerying,OptimizationHints,OptimizationHintsFetching,SafeBrowsingRealTimeUrlLookupEnabled,UseDnsHttpsSvcbAlpn",
];

export default defineConfig({
  testDir: "./e2e", testMatch: "acceptance.spec.mjs",
  workers: 1, retries: 0, timeout: 30_000, fullyParallel: false,
  outputDir: process.env.WD_TEST_OUTPUT ?? "/out/playwright",
  reporter: [["line"], ["json", { outputFile: process.env.WD_JSON_REPORT ??
    "/out/playwright-results.json" }]],
  use: {
    browserName: "chromium", headless: true, ignoreHTTPSErrors: true,
    baseURL: "https://watch.example", trace: "retain-on-failure",
    screenshot: "only-on-failure", video: "retain-on-failure",
    launchOptions: { args: chromiumControls },
  },
});
