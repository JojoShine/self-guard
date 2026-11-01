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
    async function chooseSize(scope,size){await scope.locator('.ant-pagination-options .ant-select:not(.ant-select-disabled)').click();await page.locator(`.ant-select-dropdown:visible .ant-select-item-option[title="${size} 条/页"]`).click();}
    async function settled(scope,count){await page.waitForFunction(({selector,count})=>document.querySelectorAll(selector+' .ant-table-tbody .ant-table-row').length===count,{selector:scope,count});}
    const entries=Array.from({length:65},(_,index)=>{const name='Entry-'+String(index+1).padStart(3,'0');return {id:name,name,title:name,business:name,hostname:name+'.example',version:name,day:name,actor:'read-only',createdBy:'read-only',assetCount:index,findings:index,closed:0,tasks:index,events:0,createdAt:'2026-10-31T00:00:00Z',updatedAt:'2026-10-31T00:00:00Z',availableAt:'2026-10-31T00:00:00Z',notAfter:'2028-10-31T00:00:00Z',fingerprint:name,enabled:false,status:'COMPLETED',severity:'HIGH',format:'OSV',url:'https://example.invalid/'+name,config:{mode:'ALL',conditions:[],groupBy:'asset',windowSeconds:300},parameters:[],preconditions:[],steps:[],verification:[],restore:[],impact:'只读分页检查',stopOnFailure:true,batchSize:1,targets:[],targetIds:[],enrolled:false,attempts:1,result:{total:1}};});
    const cases=[['sources','/advisories/sources'],['certificates','/certificates'],['correlation','/correlation-rules'],['templates','/repair-templates'],['batches','/workflows/batches'],['rollouts','/rollouts'],['deliveries','/maintenance/deliveries'],['imports','/governance/imports'],['business','/operations/business-groups'],['trends','/operations/trends'],['exports','/operations/exports'],['credentials','/operations/credentials']];
    await page.route('**/api/**',route=>{const path=new URL(route.request().url()).pathname.slice(4);if(route.request().method()!=='GET'||!cases.some(([,endpoint])=>endpoint===path))return route.continue();return route.fulfill({contentType:'application/json',body:JSON.stringify(path==='/rollouts'?entries:{items:entries,limit:100,timezone:'UTC',basis:'只读分页样本',components:{enrollmentConfigured:true,wafConfigured:true}})});});
    for(const [name] of cases){
      await page.goto('http://127.0.0.1:5180/#'+name);await page.getByRole('heading',{name:pageNames[name],level:1,exact:true}).waitFor();await settled('.page',15);
      const table=page.locator('.page .ant-table-wrapper');
      assert.equal(await table.locator('.ant-select-selection-item').textContent(),'15 条/页');
      for(const width of [1920,1440,1024,768,375]){
        await page.setViewportSize({width,height:900});await page.waitForFunction(expected=>document.querySelector('.sidebar').getBoundingClientRect().width===expected,width<992?72:232);
        assert.ok(await page.locator('.page').evaluate(element=>element.scrollWidth<=element.clientWidth+1),name+' overflow at '+width);
      }
      await table.locator('.ant-pagination-item-2').click();await settled('.page',15);await page.waitForFunction(()=>document.querySelector('.page .ant-table-row')?.getAttribute('data-row-key')==='Entry-016');
      await chooseSize(table,30);await settled('.page',30);
      const current=Number(await table.locator('.ant-pagination-item-active').textContent()),first='Entry-'+String((current-1)*30+1).padStart(3,'0');assert.equal(await table.locator('.ant-table-row').first().getAttribute('data-row-key'),first,name+' size data');
      await chooseSize(table,100);await settled('.page',65);assert.equal(await table.locator('.ant-table-row').first().getAttribute('data-row-key'),'Entry-001',name+' clamped page');
      console.log('Passed client pagination, row identity and five widths: '+name);
    }
    assert.deepEqual(errors,[]);console.log('Passed all 12 client-paginated modules; only GET response fixtures, no business changes.');
  } finally {await browser.close();}
})().catch(error=>{console.error(error.message);process.exit(1);});
