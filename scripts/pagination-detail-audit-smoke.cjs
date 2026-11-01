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
    const stamp='2026-10-31T00:00:00Z',assetId='11111111-1111-4111-8111-111111111111';let historyTotal=65;
    const mark=i=>'Entry-'+String(i+1).padStart(3,'0');
    await page.route('**/api/**',route=>{
      if(route.request().method()!=='GET')return route.continue();const url=new URL(route.request().url()),path=url.pathname.slice(4);
      const json=value=>route.fulfill({contentType:'application/json',body:JSON.stringify(value)});
      if(path==='/assets')return json({items:[{id:assetId,hostname:'Asset A',createdAt:stamp}],total:1});
      if(path==='/asset-changes'){const size=Number(url.searchParams.get('pageSize')),number=Number(url.searchParams.get('page'));return json({items:Array.from({length:Math.max(0,Math.min(size,historyTotal-(number-1)*size))},(_,i)=>({id:mark((number-1)*size+i),createdAt:stamp,actor:mark((number-1)*size+i),changes:{}})),total:historyTotal});}
      if(path.startsWith('/audit'))return json({items:[],total:0});
      if(/^\/workflows\/(assets|findings)\//.test(path)){const group=path.includes('/assets/')?'A':'B';return json(path.endsWith('/timeline')?{items:[]}:{findings:Array.from({length:65},(_,i)=>({id:'22222222-2222-4222-8222-'+String(i+1).padStart(12,'0'),title:'Related-'+group+'-'+mark(i),status:'OPEN',kind:'RISK'})),incidents:[],tasks:[]});}
      if(/^\/(assets|findings)\//.test(path)){const group=path.startsWith('/assets/')?'A':'B',id=path.split('/')[2];if(path.endsWith('/comments'))return json({items:[]});if(path.endsWith('/attachments'))return json({items:Array.from({length:65},(_,i)=>({id:mark(i),name:group+'-'+mark(i)+'.txt',size:1,author:'read-only'}))});return json({id,hostname:group==='A'?'Asset A':undefined,title:group==='B'?'Finding B':undefined,kind:group==='B'?'RISK':undefined,status:'OPEN',severity:'HIGH',createdAt:stamp});}
      return route.continue();
    });
    async function choose(scope,size){await scope.locator('.ant-pagination-options .ant-select:not(.ant-select-disabled)').click();await page.locator(`.ant-select-dropdown:visible .ant-select-item-option[title="${size} 条/页"]`).click();}
    async function first(scope,text,count){await page.waitForFunction(({selector,text,count})=>{const rows=document.querySelectorAll(selector+' .ant-table-row');return rows.length===count&&rows[0]?.textContent.includes(text);},{selector:scope,text,count});}
    await page.goto('http://127.0.0.1:5180/#assets');await page.locator('.data-panel .record-title-link').first().click();const drawer=page.locator('.record-drawer');await drawer.waitFor();
    await first('.record-subsection','Entry-001',15);await drawer.locator('.record-subsection .ant-pagination-item-3').click();await first('.record-subsection','Entry-031',15);historyTotal=7;await drawer.locator('.record-subsection .module-toolbar .ant-btn:not(.ant-btn-loading)').click();await first('.record-subsection','Entry-001',7);
    const attachments=drawer.locator('.ant-table-wrapper').filter({has:page.getByRole('columnheader',{name:'附件名称',exact:true})});await attachments.locator('.ant-table-row').first().getByText('A-Entry-001.txt',{exact:true}).waitFor();await choose(attachments,30);await attachments.locator('.ant-pagination-item-2').click();await attachments.locator('.ant-table-row').first().getByText('A-Entry-031.txt',{exact:true}).waitFor();
    const relations=drawer.locator('.related-record-list:visible');await relations.locator('.ant-list-item').first().getByText('Related-A-Entry-001',{exact:true}).waitFor();assert.equal(await relations.locator('.ant-list-item').count(),15);await relations.locator('.ant-pagination-item-2').click();await relations.locator('.ant-list-item').first().getByText('Related-A-Entry-016',{exact:true}).click();
    await drawer.locator('.ant-drawer-title').getByText('Finding B',{exact:true}).waitFor();await attachments.locator('.ant-table-row').first().getByText('B-Entry-001.txt',{exact:true}).waitFor();assert.equal(await attachments.locator('.ant-table-row').count(),15);assert.equal(await attachments.locator('.ant-select-selection-item').textContent(),'15 条/页');
    await relations.locator('.ant-list-item').first().getByText('Related-B-Entry-001',{exact:true}).waitFor();assert.equal(await relations.locator('.ant-list-item').count(),15);
    await page.setViewportSize({width:375,height:900});await choose(attachments,30);await page.waitForFunction(()=>[...document.querySelectorAll('.record-drawer .ant-table-wrapper')].find(element=>element.textContent.includes('附件名称'))?.querySelectorAll('.ant-table-row').length===30);assert.ok(await drawer.locator('.ant-drawer-body').evaluate(element=>element.scrollWidth<=element.clientWidth+1));
    assert.deepEqual(errors,[]);console.log('Passed asset-history shrink recovery, attachment/list default 15, cross-record pagination reset, mobile quantity selection and drawer bounds; no business mutations.');
  } finally {await browser.close();}
})().catch(error=>{console.error(error.message);process.exit(1);});
