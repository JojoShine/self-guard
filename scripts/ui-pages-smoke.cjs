const fs = require('fs');
const assert = require('node:assert/strict');
const {chromium} = require(process.env.PLAYWRIGHT_MODULE || 'playwright');
(async () => {
  const env = Object.fromEntries(fs.readFileSync('.env', 'utf8').split('\n').filter(line => line && !line.startsWith('#')).map(line => {const i = line.indexOf('='); return [line.slice(0, i), line.slice(i + 1)];}));
  const menuSource=fs.readFileSync('apps/web/src/main.tsx', 'utf8').split('const groups')[1].split('const names')[0];
  const pageNames = {overview:'工作台',...Object.fromEntries([...menuSource.matchAll(/\["([^"]+)",\s*"([^"]+)"\]/g)].map(match => [match[1],match[2]]))};
  const browser = await chromium.launch({headless: true, channel: 'chrome'});
  try {
    const page = await browser.newPage({viewport: {width: 1920, height: 1080}});
    const errors = [];
    page.on('pageerror', error => errors.push(error.message));
    await page.goto('http://127.0.0.1:5180');
    await page.getByLabel('邮箱').fill(env.ADMIN_EMAIL || 'admin@selfguard.local');
    await page.getByLabel('密码', {exact: true}).fill(env.ADMIN_PASSWORD);
    await page.getByRole('button', {name: /登\s*录/}).click();
    await page.getByRole('heading', {name: '工作台', exact: true}).waitFor();
    await page.goto('http://127.0.0.1:5180/#correlation');
    await page.getByRole('button', {name: '新建关联规则', exact: true}).click();
    const dialog = page.getByRole('dialog');
    await dialog.locator('.module-repeat-list').waitFor();
    // Measure final geometry independently of Ant Design's entrance scaling.
    const geometryStyle=await page.addStyleTag({content: '.ant-modal{animation:none!important;transition:none!important;transform:none!important}'});
    for (const width of [1920, 1440, 1024, 768]) {
      await page.setViewportSize({width, height: 1080});
      const gap = await dialog.evaluate(element => {
        const add = [...element.querySelectorAll('button')].find(button => button.textContent === '添加条件');
        const next = [...element.querySelectorAll('.ant-form-item')].find(item => item.querySelector('label')?.textContent === '同时创建事件');
        return next.getBoundingClientRect().top - add.getBoundingClientRect().bottom;
      });
      assert.ok(gap >= 15, `Rule add/next field gap at ${width}px: ${gap}`);
    }
    await geometryStyle.evaluate(element=>element.remove());
    await dialog.getByRole('button', {name: /取\s*消/}).click();
    await page.goto('http://127.0.0.1:5180/#backup');
    await page.locator('.module-section .ant-descriptions').waitFor();
    const detailGap = await page.locator('.module-section-body').evaluate(element => element.querySelector('.ant-collapse').getBoundingClientRect().top - element.querySelector('.ant-descriptions').getBoundingClientRect().bottom);
    assert.ok(detailGap >= 15, `Configuration/technical details gap: ${detailGap}`);
    await page.setViewportSize({width: 1920, height: 1080});
    await page.goto('http://127.0.0.1:5180/#telemetry');
    const query = page.locator('form.module-form-grid');
    await query.getByRole('button', {name: /查\s*询/}).waitFor();
    const alignment = await query.evaluate(form => {
      const input = form.querySelector('.ant-picker').getBoundingClientRect();
      const button = form.querySelector('button[type=submit]').getBoundingClientRect();
      return Math.abs(input.bottom - button.bottom);
    });
    assert.ok(alignment <= 2, `Query control vertical alignment: ${alignment}`);
    const routes = ['overview','assets','business','enroll','findings','risks','alerts','incidents','rules','baseline','rule-tools','detection','sources','correlation','telemetry','tasks','approvals','templates','batches','sites','waf-events','policies','access','nodes','policy-test','certificates','reports','trends','exports','users','design-system','credentials','audit','operations','rollouts','webhook','deliveries','backup','governance','retention','imports','notifications'];
    for (const width of [1440, 768]) {
      await page.setViewportSize({width, height: 1080});
      for (const route of routes) {
        await page.goto('http://127.0.0.1:5180/#' + route);
        await page.getByRole('heading', {name: pageNames[route], level: 1, exact: true}).waitFor();
        await page.waitForLoadState('networkidle');
        assert.equal(await page.getByText('服务暂时不可用', {exact: true}).count(), 0, `API unavailable on ${route}`);
        const overflow = await page.locator('.page').evaluate(element => element.scrollWidth - element.clientWidth);
        assert.ok(overflow <= 1, `Page overflow: ${route} at ${width}px: ${overflow}`);
        const legacy = await page.locator('.page').evaluate(element => [...element.querySelectorAll('input,select,textarea,button')].filter(control => !String(control.className).includes('ant-') && !control.closest('.ant-select,.ant-picker,.ant-upload')).length);
        assert.equal(legacy, 0, `Unstyled native controls on ${route} at ${width}px`);
        if(route === 'overview') {
          await page.locator('.dash-bar-label').first().waitFor();
          const geometry=await page.locator('.dash-root').evaluate(element => ({metric:element.querySelector('.dash-metric').getBoundingClientRect().height,copy:getComputedStyle(element.querySelector('.dash-metric-copy')).display,label:getComputedStyle(element.querySelector('.dash-bar-label')).display,track:element.querySelector('.dash-bar-track').getBoundingClientRect().width,row:element.querySelector('.dash-bar-row').getBoundingClientRect().width,column:element.querySelector('.dash-column-button')?.getBoundingClientRect().height}));
          assert.ok(geometry.metric>=92, `Metric card collapsed at ${width}px`);
          assert.equal(geometry.copy, 'flex');assert.equal(geometry.label, 'flex');
          assert.ok(geometry.track>=geometry.row-2, `Chart track shrank at ${width}px`);
          if(geometry.column!==undefined)assert.ok(geometry.column>100, `Column control collapsed at ${width}px`);
        }
      }
      console.log(`Passed ${routes.length} pages at ${width}px.`);
    }
    await page.goto('http://127.0.0.1:5180/#overview');
    await page.locator('.dash-bar-label').first().waitFor();
    await page.getByLabel('资产总数 进入对应模块', {exact:true}).click();
    await page.getByRole('heading', {name:'资产列表',level:1,exact:true}).waitFor();
    assert.equal(await page.getByRole('dialog').count(),0);
    await page.goto('http://127.0.0.1:5180/#overview');
    await page.getByText('查看每日数据', {exact: true}).click();
    await page.locator('.dash-chart-data .ant-table').waitFor();
    await page.route('**/api/operations/trends', route => route.fulfill({status:503,contentType:'application/json',body:JSON.stringify({message:'布局检查：读取失败'})}));
    await page.getByRole('button', {name:'刷新趋势',exact:true}).click();
    await page.getByText('布局检查：读取失败',{exact:true}).waitFor();
    const failureGap=await page.locator('.dash-trend .dash-card-body').evaluate(element=>element.querySelector('.dash-trend-plot').getBoundingClientRect().top-element.querySelector('.ant-alert').getBoundingClientRect().bottom);
    assert.ok(failureGap>=15, `Stale trend/error spacing: ${failureGap}`);
    assert.deepEqual(errors, []);
    console.log('Passed: dynamic rule spacing at 1920/1440/1024/768px, configuration disclosure spacing, query alignment, 42 pages at 1440/768px, Ant Design controls and trend table, metric menu navigation; no business mutations.');
  } finally {await browser.close();}
})().catch(error => {console.error(error.message); process.exit(1);});
