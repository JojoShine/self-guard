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
    const chart=page.locator('.dash-trend');
    await chart.locator('.dash-trend-plot').waitFor();
    async function check(label){
      const layout=await chart.evaluate(element=>{
        const body=element.querySelector('.dash-card-body');
        const nodes=[body,...body.querySelectorAll('*')];
        return {bodyOverflow:getComputedStyle(body).overflowY,verticalScrollers:nodes.filter(node=>/(auto|scroll)/.test(getComputedStyle(node).overflowY)&&node.scrollHeight>node.clientHeight+1).map(node=>node.className),bodyHeight:body.clientHeight,contentHeight:body.scrollHeight,footer:element.querySelector('.dash-card-footer').getBoundingClientRect().top,bodyBottom:body.getBoundingClientRect().bottom};
      });
      assert.ok(!['auto','scroll'].includes(layout.bodyOverflow),label+': chart must not create an inner scroll region');
      assert.deepEqual(layout.verticalScrollers,[],label+': inner vertical scrollers');
      assert.ok(layout.contentHeight<=layout.bodyHeight+1,label+': clipped chart content');
      assert.ok(layout.footer>=layout.bodyBottom-1,label+': footer overlaps content');
    }
    for(const width of [1920,1440,1024,768,375]){
      await page.setViewportSize({width,height:900});
      await check('Collapsed '+width);
      const before=await chart.evaluate(element=>element.getBoundingClientRect().height);
      await chart.locator('summary').click();
      await chart.locator('.ant-table-tbody .ant-table-row').last().waitFor();
      assert.equal(await chart.locator('.ant-table-tbody .ant-table-row').count(),15,'Daily data defaults to 15 rows');
      assert.equal(await chart.locator('.ant-pagination-total-text').textContent(),'共 30 条');
      await check('Expanded '+width);
      assert.ok(await chart.evaluate(element=>element.getBoundingClientRect().height)>before,'Card must grow with daily data');
      const siblingHeight=await page.locator('.dash-waf').evaluate(element=>element.getBoundingClientRect().height);
      assert.ok(siblingHeight<600,'Adjacent WAF card should not stretch with the expanded table');
      await chart.locator('summary').click();
    }
    assert.deepEqual(errors,[]);
    console.log('Passed: no vertical chart/table scrollbars or clipped content, collapsed/expanded paginated 30-day table at 1920/1440/1024/768/375px; adjacent card stays compact.');
  } finally {await browser.close();}
})().catch(error=>{console.error(error.message);process.exit(1);});
