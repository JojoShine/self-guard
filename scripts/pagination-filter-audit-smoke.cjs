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
    const stamp='2026-10-31T00:00:00Z';
    const mark=index=>'Entry-'+String(index+1).padStart(3,'0');
    let assetTotal=65,notificationTotal=65,failNotificationSize=0,holdTelemetry=false,releaseTelemetry,telemetryReceived;
    const telemetryCalls=[];
    const optionId='11111111-1111-4111-8111-111111111111';
    await page.route('**/api/assets?*',route=>{
      const p=new URL(route.request().url()).searchParams,size=Number(p.get('pageSize')),number=Number(p.get('page')||1),filtered=!!p.get('q'),total=filtered?7:assetTotal;
      if(size===100)return route.fulfill({contentType:'application/json',body:JSON.stringify({items:[{id:optionId,hostname:'Asset query option'}],total:1})});
      const items=Array.from({length:Math.max(0,Math.min(size,total-(number-1)*size))},(_,i)=>({id:'11111111-1111-4111-8111-'+String((number-1)*size+i+1).padStart(12,'0'),hostname:(filtered?'Filtered-':'All-')+mark((number-1)*size+i),createdAt:stamp}));
      return route.fulfill({contentType:'application/json',body:JSON.stringify({items,total})});
    });
    await page.route('**/api/governance/notifications?*',route=>{
      const p=new URL(route.request().url()).searchParams,size=Number(p.get('pageSize')),number=Number(p.get('page'));
      if(size===failNotificationSize)return route.fulfill({status:503,contentType:'application/json',body:JSON.stringify({message:'分页请求失败检查'})});
      return route.fulfill({contentType:'application/json',body:JSON.stringify({items:Array.from({length:Math.max(0,Math.min(size,notificationTotal-(number-1)*size))},(_,i)=>({id:mark((number-1)*size+i),title:'Notice-'+mark((number-1)*size+i),resource:'tasks',readAt:stamp,createdAt:stamp})),total:notificationTotal,unread:0})});
    });
    await page.route('**/api/telemetry?*',async route=>{
      const p=new URL(route.request().url()).searchParams,size=Number(p.get('pageSize')),number=Number(p.get('page')),filtered=!!p.get('assetId');telemetryCalls.push(Object.fromEntries(p));
      if(holdTelemetry){holdTelemetry=false;await new Promise(resolve=>{releaseTelemetry=resolve;telemetryReceived();});}
      return route.fulfill({contentType:'application/json',body:JSON.stringify({items:Array.from({length:Math.max(0,Math.min(size,65-(number-1)*size))},(_,i)=>({id:mark((number-1)*size+i),type:(filtered?'Filtered-':'All-')+mark((number-1)*size+i),source:'agent',occurredAt:stamp,data:{}})),total:65,retentionDays:30})});
    });
    await page.route('**/api/correlation-rules',route=>route.fulfill({contentType:'application/json',body:JSON.stringify({items:[{id:'rule',name:'Current rule result',severity:'HIGH',config:{mode:'ALL',conditions:[],groupBy:'asset',windowSeconds:300},enabled:false}]})}));
    await page.route('**/api/reports/detailed?*',route=>{
      const p=new URL(route.request().url()).searchParams,group=p.get('business')||'All';
      if(group==='FAIL')return route.fulfill({status:503,contentType:'application/json',body:JSON.stringify({message:'报表请求失败检查'})});
      return route.fulfill({contentType:'application/json',body:JSON.stringify({generatedAt:stamp,timezone:'UTC',basis:'只读分页检查',filters:{from:p.get('from'),to:p.get('to'),business:p.get('business')},totals:{},personal:{},repairOutcomes:{},businesses:Array.from({length:65},(_,i)=>({business:group+'-'+mark(i),assetsCreated:i,risksCreated:i,alertsCreated:0,tasksCreated:0})),trends:Array.from({length:65},(_,i)=>({day:group+'-'+mark(i),assetsCreated:i,risksCreated:i,alertsCreated:0,tasksCreated:0,closedFindings:0}))})});
    });
    async function chooseSize(scope,size){await scope.locator('.ant-pagination-options .ant-select:not(.ant-select-disabled)').click();await page.locator(`.ant-select-dropdown:visible .ant-select-item-option[title="${size} 条/页"]`).click();}
    async function first(selector,text,count){try{await page.waitForFunction(({selector,text,count})=>{const rows=document.querySelectorAll(selector+' .ant-table-row');return rows.length===count&&rows[0]?.textContent.includes(text);},{selector,text,count},{timeout:6000});}catch{throw Error('Expected '+text+' with '+count+' rows; saw '+JSON.stringify({rows:await page.locator(selector+' .ant-table-row').allTextContents(),alerts:await page.locator('.ant-alert-message').allTextContents(),errors,url:page.url()}));}}
    await page.goto('http://127.0.0.1:5180/#assets?page=4&pageSize=15');await first('.data-panel','All-Entry-046',15);
    await page.getByPlaceholder('搜索标题、名称或主机').fill('needle');await first('.data-panel','Filtered-Entry-001',7);assert.equal(new URLSearchParams((await page.evaluate(()=>location.hash)).split('?')[1]).get('page'),'1');
    await page.getByPlaceholder('搜索标题、名称或主机').fill('');await first('.data-panel','All-Entry-001',15);await chooseSize(page.locator('.data-panel'),30);await first('.data-panel','All-Entry-001',30);
    await page.locator('.data-panel .ant-pagination-item-3').click();await first('.data-panel','All-Entry-061',5);assetTotal=35;await page.locator('.heading').getByRole('button',{name:/刷新/}).click();await first('.data-panel','All-Entry-031',5);
    console.log('Passed main search reset and shrinking result count.');
    await page.goto('http://127.0.0.1:5180/#notifications');const notices=page.getByRole('region',{name:'站内通知',exact:true});await first('[aria-label="站内通知"]','Notice-Entry-001',15);
    failNotificationSize=30;await chooseSize(notices,30);await page.getByText('分页请求失败检查',{exact:true}).waitFor();assert.equal(await notices.locator('.ant-select-selection-item').textContent(),'15 条/页');assert.equal(await notices.locator('.ant-table-row').count(),15);failNotificationSize=0;
    await notices.locator('.ant-pagination-item-4').click();await first('[aria-label="站内通知"]','Notice-Entry-046',15);notificationTotal=20;await notices.locator('.module-section-extra .ant-btn:not(.ant-btn-loading)').click();await first('[aria-label="站内通知"]','Notice-Entry-016',5);
    console.log('Passed failed page-size requests and notification page recovery.');
    await page.goto('http://127.0.0.1:5180/#telemetry');const telemetry=page.getByRole('region',{name:'已脱敏日志',exact:true});await first('[aria-label="已脱敏日志"]','All-Entry-001',15);
    await telemetry.locator('form .ant-select').first().click();await page.locator('.ant-select-dropdown:visible .ant-select-item-option[title="Asset query option"]').click();
    await telemetry.locator('.ant-pagination-item-2').click();await first('[aria-label="已脱敏日志"]','All-Entry-016',15);assert.equal(telemetryCalls.at(-1).assetId,undefined);
    await telemetry.locator('form button[type=submit]:not(.ant-btn-loading)').click();await first('[aria-label="已脱敏日志"]','Filtered-Entry-001',15);
    await telemetry.locator('.ant-pagination-item-2').click();await first('[aria-label="已脱敏日志"]','Filtered-Entry-016',15);await chooseSize(telemetry,30);await first('[aria-label="已脱敏日志"]','Filtered-Entry-001',30);assert.equal(telemetryCalls.at(-1).assetId,optionId);
    await telemetry.locator('form .ant-select').first().hover();await telemetry.locator('form .ant-select-clear').click();await telemetry.locator('.ant-pagination-item-2').click();await first('[aria-label="已脱敏日志"]','Filtered-Entry-031',30);assert.equal(telemetryCalls.at(-1).assetId,optionId);
    await telemetry.locator('form button[type=submit]:not(.ant-btn-loading)').click();await first('[aria-label="已脱敏日志"]','All-Entry-001',30);
    holdTelemetry=true;const received=new Promise(resolve=>{telemetryReceived=resolve;});await telemetry.locator('.ant-pagination-item-2').click();await received;
    await page.goto('http://127.0.0.1:5180/#correlation');await first('[aria-label="关联规则"]','Current rule result',1);const finished=page.waitForResponse(result=>result.url().includes('/api/telemetry?'));releaseTelemetry();await finished;await page.waitForLoadState('networkidle');await first('[aria-label="关联规则"]','Current rule result',1);
    console.log('Passed applied telemetry filters across page/size changes and stale response isolation.');
    await page.goto('http://127.0.0.1:5180/#reports');const businesses=page.getByRole('region',{name:'业务分布',exact:true}),trends=page.getByRole('region',{name:'创建日期趋势（UTC）',exact:true});await first('[aria-label="业务分布"]','All-Entry-001',15);
    await chooseSize(businesses,30);await businesses.locator('.ant-pagination-item-2').click();await first('[aria-label="业务分布"]','All-Entry-031',30);await trends.locator('.ant-pagination-item-3').click();await first('[aria-label="创建日期趋势（UTC）"]','All-Entry-031',15);
    await page.getByLabel('业务名称',{exact:true}).fill('B');await page.getByRole('region',{name:'报告筛选',exact:true}).locator('button[type=submit]:not(.ant-btn-loading)').click();await first('[aria-label="业务分布"]','B-Entry-001',30);await first('[aria-label="创建日期趋势（UTC）"]','B-Entry-001',15);assert.equal(await businesses.locator('.ant-select-selection-item').textContent(),'30 条/页');
    await businesses.locator('.ant-pagination-item-2').click();await first('[aria-label="业务分布"]','B-Entry-031',30);await page.getByLabel('业务名称',{exact:true}).fill('FAIL');await page.getByRole('region',{name:'报告筛选',exact:true}).locator('button[type=submit]:not(.ant-btn-loading)').click();await page.getByText('报表请求失败检查',{exact:true}).waitFor();await first('[aria-label="业务分布"]','B-Entry-031',30);
    assert.deepEqual(errors,[]);console.log('Passed report filter resets with size preservation and failed-filter snapshot retention; no business mutations.');
  } finally {await browser.close();}
})().catch(error=>{console.error(error.message);process.exit(1);});
