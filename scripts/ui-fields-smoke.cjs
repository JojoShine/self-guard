const fs = require('fs');
const assert = require('node:assert/strict');
const {chromium} = require(process.env.PLAYWRIGHT_MODULE || 'playwright');
(async () => {
  const env = Object.fromEntries(fs.readFileSync('.env', 'utf8').split('\n').filter(line => line && !line.startsWith('#')).map(line => {
    const separator = line.indexOf('=');
    return [line.slice(0, separator), line.slice(separator + 1)];
  }));
  const browser = await chromium.launch({headless: true, channel: 'chrome'});
  try {
    const page = await browser.newPage({viewport: {width: 1440, height: 1000}});
    const errors = [];
    page.on('pageerror', error => errors.push(error.message));
    await page.goto('http://127.0.0.1:5180');
    await page.getByLabel('邮箱').fill(env.ADMIN_EMAIL || 'admin@selfguard.local');
    await page.getByLabel('密码', {exact: true}).fill(env.ADMIN_PASSWORD);
    await page.getByRole('button', {name: /登\s*录/}).click();
    await page.getByRole('heading', {name: '工作台', exact: true}).waitFor();
    await page.goto('http://127.0.0.1:5180/#imports');
    const section = page.getByRole('region', {name: '外部结果导入', exact: true});
    await section.getByRole('button', {name: '导入外部结果', exact: true}).waitFor();
    for (const width of [1920, 1440, 1024, 768]) {
      await page.setViewportSize({width, height: 1000});
      const gap = await section.evaluate(element => {
        const actions = element.querySelector('.module-toolbar').getBoundingClientRect();
        const note = element.querySelector('.module-note').getBoundingClientRect();
        return note.top - actions.bottom;
      });
      assert.ok(gap >= 15, `Import description gap at ${width}px: ${gap}`);
    }
    await page.setViewportSize({width: 1440, height: 1000});
    await page.goto('http://127.0.0.1:5180/#assets');
    await page.locator('.advanced-trigger').click();
    const from = page.getByRole('textbox', {name: '创建起日（UTC）', exact: true});
    await from.click();
    await page.locator('.ant-picker-dropdown:not(.ant-picker-dropdown-hidden)').waitFor();
    await from.fill('2026-10-01');
    await from.press('Enter');
    await page.waitForFunction(() => location.hash.includes('createdFrom=2026-10-01T00%3A00%3A00.000Z'));
    const picker = page.locator('.advanced-query .ant-picker').first();
    await picker.hover();
    await picker.locator('.ant-picker-clear').click();
    await page.waitForFunction(() => !location.hash.includes('createdFrom='));
    await page.locator('.ant-table-tbody .record-title-link').first().click();
    const drawer = page.locator('.record-drawer');
    assert.equal(await drawer.getByRole('button', {name: '执行器结果验签', exact: true}).count(),0);
    await drawer.getByRole('button', {name: /上传附件$/}).waitFor();
    for (const width of [1920, 1440, 1024, 768]) {
      await page.setViewportSize({width, height: 1000});
      const gaps = await drawer.evaluate(element => {
        const inventory = element.querySelector('.asset-inventory-view');
        const upload = element.querySelector('.evidence-upload');
        return {
          groups: inventory.querySelector('h3').getBoundingClientRect().top - inventory.previousElementSibling.getBoundingClientRect().bottom,
          attachment: upload.nextElementSibling.getBoundingClientRect().top - upload.getBoundingClientRect().bottom,
          overflow: element.querySelector('.ant-drawer-body').scrollWidth - element.querySelector('.ant-drawer-body').clientWidth,
        };
      });
      assert.ok(gaps.groups >= 15, `Detail action group gap at ${width}px: ${gaps.groups}`);
      assert.ok(gaps.attachment >= 15, `Attachment table gap at ${width}px: ${gaps.attachment}`);
      assert.ok(gaps.overflow <= 1, `Drawer overflows at ${width}px: ${gaps.overflow}`);
    }
    const uploads = [];
    page.on('request', request => { if (request.method() === 'POST' && request.url().includes('/attachments')) uploads.push(request.url()); });
    await drawer.locator('.ant-upload input[type=file]').setInputFiles({name: 'too-large.txt', mimeType: 'text/plain', buffer: Buffer.alloc(1024 * 1024 + 1)});
    await drawer.getByText('附件不能超过 1 MiB', {exact: true}).waitFor();
    assert.equal(uploads.length, 0, 'Oversized files must not be uploaded');
    assert.deepEqual(errors, []);
    console.log('Passed: import/action/upload spacing and drawer overflow at 1920/1440/1024/768px; calendar selection and clear preserve UTC filters; oversized Upload rejected without sending attachments.');
  } finally { await browser.close(); }
})().catch(error => { console.error(error.message); process.exit(1); });
