import { test } from "@playwright/test";
import { scanPastedHtml, signIn } from "./journey.mjs";

test("operator-invoked headed rehearsal reuses the asserted journey", async ({ page }) => {
  await signIn(page);
  await scanPastedHtml(page, "<a href='https://example.com/security'>Example evidence</a>");
  await page.screenshot({ path: "artifacts/operator-recording/paste-scan.png", fullPage: true });
  await page.goto("/reference");
  await page.locator("#delayed-live-anchor").waitFor();
  await page.getByRole("button", { name: "Inspect current rendered anchors" }).click();
  await page.locator(".result-card").first().waitFor();
  await page.screenshot({ path: "artifacts/operator-recording/live-page-scan.png", fullPage: true });
});
