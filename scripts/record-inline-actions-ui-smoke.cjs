// UI-only fixture for single-layer list actions. Never changes a real asset or executor key.
const fs = require('node:fs'), assert = require('node:assert/strict');
const {chromium} = require(process.env.PLAYWRIGHT_MODULE || 'playwright');
const env = Object.fromEntries(fs.readFileSync('.env', 'utf8').split(/\r?\n/).filter(line => line.includes('=')).map(line => { const index = line.indexOf('='); return [line.slice(0, index), line.slice(index + 1)]; }));
async function main() {
  const login = await fetch('http://127.0.0.1:4010/api/auth/login', {method: 'POST', headers: {'content-type': 'application/json'}, body: JSON.stringify({email: env.ADMIN_EMAIL || 'admin@selfguard.local', password: env.ADMIN_PASSWORD})});
  assert.ok(login.ok);
  const {token} = await login.json(), browser = await chromium.launch({headless: true, channel: 'chrome'});
  try {
    for (const width of (process.env.RECORD_ACTION_WIDTHS||'1920,1440,1280,768,390').split(',').map(Number)) {
      const page = await browser.newPage({viewport: {width, height: 1000}});
      page.setDefaultTimeout(15000);
      await page.addInitScript(token => sessionStorage.setItem('sg-token', token), token);
      const id = 'record-inline-ui-fixture', row = {id, hostname: '内联操作验收主机', os: 'linux', ip: '192.0.2.10', tags: [], archivedAt: null, executorPublicKey: Buffer.alloc(32, 2).toString('base64')};
      const writes = [];
      let failKey = true, failArchive = true;
      await page.route('**/api/**', async route => {
        const request = route.request(), url = new URL(request.url()), path = url.pathname;
        if (path === '/api/assets/' + id && request.method() === 'PATCH') {
          const body = request.postDataJSON(); writes.push(body);
          assert.deepEqual(Object.keys(body), ['executorPublicKey']);
          if (failKey) { failKey = false; return route.fulfill({status: 422, json: {message: '夹具：公钥校验失败'}}); }
          row.executorPublicKey = body.executorPublicKey;
          return route.fulfill({json: row});
        }
        if (path === '/api/workflows/assets/' + id + '/archive') {
          assert.equal(request.method(), 'POST');
          const body = request.postDataJSON(); writes.push(body);
          if (failArchive) { failArchive = false; return route.fulfill({status: 409, json: {message: '夹具：执行中任务不能归档'}}); }
          row.archivedAt = body.archived ? new Date().toISOString() : null;
          return route.fulfill({json: row});
        }
        assert.equal(request.method(), 'GET', 'Unexpected mutation outside the owned UI fixture');
        if (path === '/api/assets') return route.fulfill({json: {items: [row], total: 1}});
        if (path === '/api/assets/' + id) return route.fulfill({json: row});
        if (path.startsWith('/api/assets/' + id + '/') || path === '/api/asset-changes') return route.fulfill({json: {items: [], total: 0}});
        return route.continue();
      });
      await page.goto('http://127.0.0.1:5180/#assets');
      const drawer = page.locator('.ant-drawer-open .ant-drawer-content');
      async function more(label){await page.getByRole('button',{name:'更多操作',exact:true}).click();await page.getByRole('menuitem',{name:label,exact:true}).click()}
      await more('执行器结果验签');
      const editor = drawer.getByRole('region', {name: '执行器结果公钥'});
      console.log('CHECK public key editor at ' + width);
      await page.waitForFunction(() => {
        const element = document.querySelector('[aria-label="执行器结果公钥"]');
        const box = element?.getBoundingClientRect();
        return box && box.width > 0 && box.left >= 0 && box.right <= innerWidth + 1;
      });
      const bounds = await editor.boundingBox();
      assert.ok(bounds && bounds.x >= 0 && bounds.x + bounds.width <= width + 1, 'Inline editor exceeds the viewport');
      await editor.getByLabel('Ed25519 原始 32 字节公钥（Base64）').fill('');
      await editor.getByRole('button', {name: '保存公钥', exact: true}).click();
      await editor.getByText('请填写受信执行器导出的公钥', {exact: true}).waitFor();
      console.log('CHECK empty key rejected at ' + width);
      assert.equal(writes.length, 0);
      const key = Buffer.alloc(32, 3).toString('base64');
      await editor.getByLabel('Ed25519 原始 32 字节公钥（Base64）').fill(key);
      await editor.getByRole('button', {name: '保存公钥', exact: true}).click();
      await editor.getByText('夹具：公钥校验失败', {exact: true}).waitFor();
      console.log('CHECK failed save retained at ' + width);
      await editor.getByRole('button', {name: '保存公钥', exact: true}).click();
      await editor.waitFor({state: 'hidden'});
      assert.equal(row.executorPublicKey, key);
      await more('执行器结果验签');
      await editor.getByRole('button', {name: '停用验签', exact: true}).click();
      await editor.getByText('该资产将不再强制要求受信执行器签名。', {exact: false}).waitFor();
      await editor.getByRole('button', {name: '保留验签', exact: true}).click();
      assert.equal(row.executorPublicKey, key);
      await editor.getByRole('button', {name: '停用验签', exact: true}).click();
      await editor.getByRole('button', {name: '确认停用验签', exact: true}).click();
      await editor.waitFor({state: 'hidden'});
      assert.equal(row.executorPublicKey, null);
      await more('归档资产');
      const archive = drawer.getByRole('region', {name: '归档资产', exact: true});
      await archive.getByRole('button', {name: '确认归档资产', exact: true}).click();
      await archive.getByText('夹具：执行中任务不能归档', {exact: true}).waitFor();
      assert.equal(row.archivedAt, null);
      await archive.getByRole('button', {name: '确认归档资产', exact: true}).click();
      await archive.waitFor({state: 'hidden'});
      await more('恢复资产');
      const restore = drawer.getByRole('region', {name: '恢复资产', exact: true});
      await restore.getByRole('button', {name: '确认恢复资产', exact: true}).click();
      await restore.waitFor({state: 'hidden'});
      assert.equal(row.archivedAt, null);
      assert.equal(await page.locator('.ant-modal-wrap:visible').count(), 0);
      assert.equal(await page.locator('.ant-drawer-open').count(), 0);
      assert.equal(new URL(page.url()).hash.split('?')[0], '#assets');
      assert.ok(await page.locator('.sidebar .ant-menu-item-selected, .sidebar .ant-menu-submenu-selected').count() >= 1);
      assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1));
      console.log('PASS single-layer list key/archive/recovery, actual payloads, errors and no nested dialogs at ' + width);
      await page.close();
    }
  } finally { await browser.close(); }
}
main().catch(error => { console.error(error.message); process.exitCode = 1; });
