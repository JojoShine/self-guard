const fs = require("node:fs");
const path = require("node:path");
const assert = require("node:assert/strict");
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || "playwright");
const root = path.resolve(__dirname, "..");
let adminPassword = "";
(async () => {
  const env = Object.fromEntries(fs.readFileSync(path.join(root, ".env"), "utf8").trim().split("\n").map(line => {
    const split = line.indexOf("="); return [line.slice(0, split), line.slice(split + 1)];
  }));
  adminPassword = env.ADMIN_PASSWORD;
  const browser = await chromium.launch({ headless: true, channel: "chrome" });
  const page = await browser.newPage({ viewport: { width: 1440, height: 1000 } });
  const errors = [];
  page.on("pageerror", error => errors.push(error.message));
  const externalRequests = [];
  page.on("request", request => {
    if (new URL(request.url()).hostname === "api.osv.dev") externalRequests.push(request.url());
  });
  try {
    await page.goto("http://127.0.0.1:5180");
    await page.getByLabel("邮箱").fill(env.ADMIN_EMAIL);
    await page.getByLabel("密码", { exact: true }).fill(env.ADMIN_PASSWORD);
    await page.getByRole("button", { name: /登\s*录/ }).click();
    await page.getByRole("heading", { name: "工作台", exact: true }).waitFor({ timeout: 15000 });
    await page.goto("http://127.0.0.1:5180/#sources");
    await page.getByRole("button", { name: "添加漏洞数据源", exact: true }).click();
    const mark = Date.now();
    const name = "浏览器验证停用源 " + mark;
    const sourceUrl = "https://api.osv.dev/v1/vulns/SELF-GUARD-BROWSER-" + mark;
    await page.getByLabel("数据源名称", { exact: true }).fill(name);
    await page.getByLabel("通告地址", { exact: true }).fill(sourceUrl);
    await page.getByRole("switch").click();
    assert.equal(await page.getByRole("switch").isChecked(), false);
    await page.getByRole("button", { name: "保存数据源", exact: true }).click();
    let row = page.getByRole("row").filter({ hasText: name });
    await row.waitFor();
    assert.equal(await row.getByRole("button", { name: "同步通告", exact: true }).isDisabled(), true);
    await row.getByRole("button", { name: "编辑数据源", exact: true }).click();
    await page.getByLabel("数据源名称", { exact: true }).fill(name + " 已编辑");
    assert.equal(await page.getByRole("switch").isChecked(), false);
    await page.getByRole("button", { name: "保存数据源", exact: true }).click();
    row = page.getByRole("row").filter({ hasText: name + " 已编辑" });
    await row.waitFor();
    const saved = await page.evaluate(async url => {
      const response = await fetch("/api/advisories/sources", { headers: { Authorization: "Bearer " + sessionStorage.getItem("sg-token") } });
      const data = await response.json(); return data.items.find(item => item.url === url);
    }, sourceUrl);
    assert.equal(saved.enabled, false);
    assert.equal(saved.status, "IDLE");
    assert.equal(saved.lastSyncAt, null);
    assert.equal(saved.name, name + " 已编辑");
    assert.deepEqual(externalRequests, []);
    assert.deepEqual(errors, []);
    fs.mkdirSync(path.join(root, ".artifacts/results"), { recursive: true });
    await page.screenshot({ path: path.join(root, ".artifacts/results/advisories-browser.png"), fullPage: true });
    console.log("Advisory browser passed: create, list and edit disabled source; sync remains disabled; no external requests or runtime errors.");
  } finally { await browser.close(); }
})().catch(error => {
  console.error(adminPassword ? error.message.split(adminPassword).join("[REDACTED]") : error.message);
  process.exitCode = 1;
});
