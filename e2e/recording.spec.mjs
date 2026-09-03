import { test } from "@playwright/test";
import { runAssertedJourney } from "./journey.mjs";

test("operator-invoked headed rehearsal reuses the asserted journey", async ({ page, context }, testInfo) => {
  await runAssertedJourney(page, context, {
    afterPaste: async (currentPage) => currentPage.screenshot({
      path: testInfo.outputPath("paste-scan.png"), fullPage: true,
    }),
    afterLive: async (currentPage) => currentPage.screenshot({
      path: testInfo.outputPath("live-page-scan.png"), fullPage: true,
    }),
  });
});
