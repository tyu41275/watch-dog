import { test, expect } from "@playwright/test";
import { runJourney } from "./journey.mjs";
test("operator-invoked headed recording reuses the asserted journey", async ({ page }) => {
  await runJourney(page, expect);
});
