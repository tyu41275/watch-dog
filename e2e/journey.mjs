export const judge = {
  username: "playwright-judge", password: "synthetic-browser-fixture",
};
export async function signIn(page) {
  await page.goto("/");
  await page.getByLabel("Username").fill(judge.username); await page.getByLabel("Password").fill(judge.password);
  await page.getByRole("button", { name: "Sign in" }).click();
  await page.locator("#scan-panel").waitFor({ state: "visible" });
}
export async function scanPastedHtml(page, html = "<a href='./one'>One</a>") {
  await page.locator("#provider-consent").check();
  await page.getByLabel("Effective base URL").fill("https://example.com/base/"); await page.getByLabel("HTML").fill(html);
  await page.getByRole("button", { name: "Scan inert HTML" }).click();
  await page.locator(".result-card").first().waitFor();
}
