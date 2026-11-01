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
    let expectedAssetTotal=7;
    await page.route('**/api/assets?*',route=>{
      const url=new URL(route.request().url());if(url.searchParams.get('pageSize')==='100')return route.continue();
      const size=Number(url.searchParams.get('pageSize')),number=Number(url.searchParams.get('page'));
      return route.fulfill({contentType:'application/json',body:JSON.stringify({items:Array.from({length:Math.max(0,Math.min(size,expectedAssetTotal-(number-1)*size))},(_,i)=>({id:'test-asset-'+i,hostname:'Filtered-Entry-'+((number-1)*size+i+1),os:'linux',ip:'192.0.2.1',business:'test',createdAt:'2026-10-31T00:00:00Z'})),total:expectedAssetTotal})});
    });
    await page.goto('http://127.0.0.1:5180/#assets?page=9&pageSize=15');
    await page.waitForFunction(()=>new URLSearchParams(location.hash.split('?')[1]).get('page')==='1',{},{timeout:5000});
    await page.waitForFunction(()=>document.querySelectorAll('.data-panel .ant-table-row').length===7);
    assert.deepEqual(errors,[]);
    console.log('Passed out-of-range server pagination recovery.');
  } finally {await browser.close();}
})().catch(error=>{console.error(error.message);process.exit(1);});
