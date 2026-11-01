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
    async function get(path){const result=await page.evaluate(async path=>{const response=await fetch('/api'+path,{headers:{Authorization:'Bearer '+sessionStorage.getItem('sg-token')}});return {status:response.status,body:await response.json()};},path);assert.equal(result.status,200,path);return result.body;}
    const nodes=await get('/waf-nodes?page=1&pageSize=15&sortBy=lastSeen&order=desc');assert.equal(typeof nodes.total,'number');assert.ok(nodes.items.length<=15);
    if(nodes.items.length){const filtered=await get('/waf-nodes?page=1&pageSize=15&q='+encodeURIComponent(nodes.items[0].id));assert.ok(filtered.items.some(item=>item.id===nodes.items[0].id));}
    const emptyNodes=await get('/waf-nodes?page=1&pageSize=15&q=__pagination_no_match__');assert.equal(emptyNodes.total,0);assert.equal(emptyNodes.items.length,0);
    const access=await get('/waf-access?page=1&pageSize=15&sortBy=timestamp&order=desc&createdFrom=2020-01-01T00%3A00%3A00.000Z');assert.equal(typeof access.total,'number');assert.ok(access.items.length<=15);
    const emptyAccess=await get('/waf-access?page=1&pageSize=15&q=__pagination_no_match__');assert.equal(emptyAccess.total,0);
    for(const [route,dateLabel,sort] of [['nodes','心跳起日（UTC）','最近心跳'],['access','访问起日（UTC）','访问时间']]){
      await page.goto('http://127.0.0.1:5180/#'+route);await page.getByRole('heading',{name:pageNames[route],level:1,exact:true}).waitFor();await page.waitForLoadState('networkidle');
      await page.locator('.advanced-trigger').click();await page.getByLabel(dateLabel,{exact:true}).waitFor();assert.equal(await page.locator('.query-grid .ant-select-selection-item').first().textContent(),sort);
      await page.getByPlaceholder('搜索标题、名称或主机').fill('__pagination_no_match__');await page.waitForFunction(()=>document.querySelector('.result-count strong')?.textContent==='0');assert.equal(await page.locator('.data-panel .ant-table-row').count(),0);assert.equal(await page.getByText('服务暂时不可用',{exact:true}).count(),0);
    }
    assert.deepEqual(errors,[]);console.log('Passed real WAF node/access pagination totals, search, date bounds, menu pages and resource-specific filter labels; GET only.');
  } finally {await browser.close();}
})().catch(error=>{console.error(error.message);process.exit(1);});
