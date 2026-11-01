const fs = require("fs");
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || "playwright");
(async () => {
  const env = Object.fromEntries(
    fs
      .readFileSync(".env", "utf8")
      .trim()
      .split("\n")
      .map((l) => {
        const i = l.indexOf("=");
        return [l.slice(0, i), l.slice(i + 1)];
      }),
  );
  const browser = await chromium.launch({ headless: true, channel: "chrome" });
  const page = await browser.newPage({
    viewport: { width: 1440, height: 1000 },
  });
  const errors = [];
  page.on("pageerror", (e) => errors.push(e.message));
  await page.goto("http://127.0.0.1:5180");
  await page.getByLabel("邮箱").fill(env.ADMIN_EMAIL);
  await page.getByLabel("密码", { exact: true }).fill(env.ADMIN_PASSWORD);
  await page.getByRole("button", { name: /登\s*录/ }).click();
  await page
    .getByRole("heading", { name: "工作台", exact: true })
    .waitFor({ timeout: 15000 });
  for (const route of [
    "assets",
    "findings",
    "risks",
    "incidents",
    "rules",
    "tasks",
    "sites",
    "users",
    "audit", "governance", "retention", "imports", "notifications", "sources", "batches",
  ]) {
    await page.goto("http://127.0.0.1:5180/#" + route);
    await page.waitForTimeout(350);
    if (await page.getByText("服务暂时不可用", { exact: true }).count())
      throw new Error(route + " API failed");
  }
  await page.goto("http://127.0.0.1:5180/#findings");
  await page.waitForTimeout(500);
  fs.mkdirSync(".artifacts", { recursive: true });
  await page.screenshot({
    path: ".artifacts/security-center.png",
    fullPage: true,
  });
  if (errors.length) throw new Error(errors.join("\n"));
  console.log("Browser smoke passed: login, main and governance routes, no runtime exceptions.");
  await browser.close();
})().catch((e) => {
  console.error(e.message);
  process.exit(1);
});
