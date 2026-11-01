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
    async function chooseSize(scope,size){
      await scope.locator('.ant-pagination-options .ant-select').click();
      const popup=page.locator('.ant-select-dropdown:visible');
      for(const value of [15,30,50,100])assert.equal(await popup.locator(`.ant-select-item-option[title="${value} 条/页"]`).count(),1);
      await popup.locator(`.ant-select-item-option[title="${size} 条/页"]`).click();
    }
    async function rows(scope,count){await page.waitForFunction(({selector,count})=>document.querySelectorAll(selector+' .ant-table-tbody .ant-table-row').length===count,{selector:scope,count});}
    function response(path,size,number=1){return page.waitForResponse(result=>{const url=new URL(result.url());return url.pathname==='/api/'+path&&url.searchParams.get('pageSize')===String(size)&&url.searchParams.get('page')===String(number)&&result.status()===200;});}
    await Promise.all([response('assets',15),page.goto('http://127.0.0.1:5180/#assets')]);
    const main=page.locator('.data-panel');await rows('.data-panel',15);
    await Promise.all([response('assets',15,2),main.locator('.ant-pagination-item-2').click()]);
    await Promise.all([response('assets',30),chooseSize(main,30)]);await rows('.data-panel',30);
    await page.waitForFunction(()=>location.hash.includes('pageSize=30')&&new URLSearchParams(location.hash.split('?')[1]).get('page')==='1');
    await Promise.all([response('assets',30),page.reload()]);await rows('.data-panel',30);
    await Promise.all([response('assets',100),chooseSize(main,100)]);await rows('.data-panel',100);
    await page.route('**/api/asset-changes?*',route=>{const url=new URL(route.request().url()),size=Number(url.searchParams.get('pageSize')),number=Number(url.searchParams.get('page'));return route.fulfill({contentType:'application/json',body:JSON.stringify({items:Array.from({length:Math.min(size,67-(number-1)*size)},(_,i)=>({id:'history-'+((number-1)*size+i),createdAt:'2026-10-31T00:00:00Z',actor:'分页检查',changes:{os:{from:'old',to:'new'}}})),total:67})});});
    await Promise.all([response('asset-changes',15),main.locator('.record-title-link').first().click()]);
    const history=page.locator('.record-subsection .ant-table-wrapper');await rows('.record-subsection',15);
    await Promise.all([response('asset-changes',50),chooseSize(history,50)]);await rows('.record-subsection',50);
    await page.locator('.record-drawer .ant-drawer-close').click();
    for(const path of ['telemetry','governance/notifications']){
      await page.route('**/api/'+path+'?*',route=>{const url=new URL(route.request().url()),size=Number(url.searchParams.get('pageSize')),number=Number(url.searchParams.get('page'));const items=Array.from({length:Math.min(size,65-(number-1)*size)},(_,i)=>({id:path+'-'+((number-1)*size+i),title:'分页检查',resource:'tasks',readAt:'2026-10-31T00:00:00Z',createdAt:'2026-10-31T00:00:00Z',occurredAt:'2026-10-31T00:00:00Z',type:'PAGINATION_CHECK',source:'agent',data:{}}));return route.fulfill({contentType:'application/json',body:JSON.stringify({items,total:65,unread:0,retentionDays:30})});});
      const route=path==='telemetry'?'telemetry':'notifications';
      await Promise.all([response(path,15),page.goto('http://127.0.0.1:5180/#'+route)]);
      const scope=path==='telemetry'?page.getByRole('region',{name:'已脱敏日志',exact:true}):page.getByRole('region',{name:'站内通知',exact:true});
      await Promise.all([response(path,50),chooseSize(scope,50)]);
      await page.waitForFunction(()=>document.querySelectorAll('.module-section .ant-table-tbody .ant-table-row').length===50);
    }
    await page.goto('http://127.0.0.1:5180/#reports');
    const trend=page.getByRole('region',{name:'创建日期趋势（UTC）',exact:true});await trend.locator('.ant-table-row').first().waitFor();
    assert.equal(await trend.locator('.ant-table-row').count(),15);
    await chooseSize(trend,30);assert.equal(await trend.locator('.ant-table-row').count(),30);
    await page.goto('http://127.0.0.1:5180/#overview');
    const chart=page.locator('.dash-trend');await chart.locator('.dash-trend-plot').waitFor();await chart.locator('summary').click();
    assert.equal(await chart.locator('.ant-table-row').count(),15);
    await chooseSize(chart,30);assert.equal(await chart.locator('.ant-table-row').count(),30);
    assert.ok(await chart.locator('.dash-card-body').evaluate(element=>getComputedStyle(element).overflowY==='visible'&&element.scrollHeight<=element.clientHeight+1));
    await page.goto('http://127.0.0.1:5180/#templates');
    for(const width of [1440,768,375]){await page.setViewportSize({width,height:900});await page.waitForLoadState('networkidle');assert.ok(await page.locator('.page').evaluate(element=>element.scrollWidth<=element.clientWidth+1),'Pagination overflow at '+width);assert.equal(await page.locator('.ant-pagination-options .ant-select-selection-item').textContent(),'15 条/页');}
    assert.deepEqual(errors,[]);
    console.log('Passed: default 15, size options 15/30/50/100, main page reset and reload, server requests for assets/history/telemetry/notifications, report/trend client paging, no inner chart scrolling, responsive controls at 1440/768/375px.');
  } finally {await browser.close();}
})().catch(error=>{console.error(error.message);process.exit(1);});
