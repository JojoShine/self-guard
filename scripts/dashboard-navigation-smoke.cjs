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
    let detailRequests=0;
    page.on('request',request=>{if(request.url().includes('/api/workload/details'))detailRequests++;});
    async function home(){await page.goto('http://127.0.0.1:5180/#overview');await page.locator('.workload-health .dash-bar-row').first().waitFor();}
    async function destination(route){
      await page.getByRole('heading',{name:pageNames[route],level:1,exact:true}).waitFor();
      assert.equal(await page.getByRole('dialog').count(),0,'Home navigation must not open dialogs');
      assert.equal(await page.locator('.record-drawer:visible').count(),0,'Home navigation must not open a record drawer');
      assert.ok(await page.locator('.sidebar .ant-menu-item-selected,.sidebar .ant-menu-submenu-selected').count()>0,'Destination menu must be selected');
    }
    for(const width of [1440,768]){
      await page.setViewportSize({width,height:1080});
      for(const [group,route] of Object.entries({overviewAssets:'assets',overviewRisks:'risks',overviewAlerts:'alerts',overviewTasks:'tasks',overviewCritical:'risks',overviewIncidents:'incidents',wafEvents:'waf-events',wafBlocked:'waf-events'})){
        await home();await page.locator(`[data-metric-group="${group}"]`).click();await destination(route);
      }
      for(const [section,index,route] of [['workload-health',0,'assets'],['workload-health',1,'assets'],['workload-health',2,'assets'],['workload-health',3,'assets'],['workload-outcomes',0,'tasks'],['workload-outcomes',1,'tasks'],['workload-outcomes',2,'tasks']]){
        await home();await page.locator(`.${section} .dash-bar-row`).nth(index).click();await destination(route);
      }
      await home();await page.locator('.dash-column-button').first().click();await destination('assets');
      await home();await page.locator('.dash-column-button').nth(1).click();await destination('risks');
      for(const [tab,route] of [['待我审批','approvals'],['我的任务','tasks'],['分派给我','findings'],['已逾期','findings']]){
        await home();await page.getByRole('tab',{name:new RegExp('^'+tab)}).click();await page.locator('.workload-tasks').getByRole('button',{name:/查看全部/}).click();await destination(route);
      }
      await home();await page.locator('.workload-verification').getByRole('button',{name:/^发现/}).click();await destination('findings');
      await home();await page.locator('.workload-verification').getByRole('button',{name:/^任务/}).click();await destination('tasks');
      await home();await page.locator('.dash-waf-counter').first().click();await destination('nodes');
      await home();const recent=page.locator('.dash-recent .dash-record-title').first();if(await recent.count()){await recent.click();await page.locator('.page h1').waitFor();await page.waitForFunction(()=>!location.hash.startsWith('#overview'));assert.equal(await page.getByRole('dialog').count(),0);assert.equal(await page.locator('.record-drawer:visible').count(),0);}
      await home();
      const colors=await page.locator('.dash-root').evaluate(element=>Object.fromEntries(['primary','success','warning','cyan','violet'].map(tone=>{const node=element.querySelector('.chart-background--'+tone);return [tone,node?getComputedStyle(node).backgroundColor:null];})));
      assert.deepEqual(colors,{primary:'rgb(52, 120, 246)',success:'rgb(34, 197, 94)',warning:'rgb(250, 140, 22)',cyan:'rgb(19, 194, 194)',violet:'rgb(146, 84, 222)'});
      const overflow=await page.locator('.page').evaluate(element=>element.scrollWidth-element.clientWidth);assert.ok(overflow<=1);
      await page.screenshot({path:'.artifacts/results/dashboard-navigation-'+width+'.png',fullPage:true});
      await page.goto('http://127.0.0.1:5180/#assets');await page.locator('.record-title-link').first().waitFor();
      const link=await page.locator('.record-title-link').first().evaluate(element=>({color:getComputedStyle(element).color,weight:getComputedStyle(element).fontWeight}));assert.deepEqual(link,{color:'rgb(37, 95, 212)',weight:'600'});
      await page.goto('http://127.0.0.1:5180/#templates');await page.locator('.module-record-title').first().waitFor();
      const text=await page.locator('.module-record-title').first().evaluate(element=>({color:getComputedStyle(element).color,weight:getComputedStyle(element).fontWeight}));assert.deepEqual(text,{color:'rgb(32, 43, 64)',weight:'400'});
      console.log(`Passed dashboard menu navigation, vivid chart colors, clickable/plain list text and layout at ${width}px.`);
    }
    assert.equal(detailRequests,0,'Home must not request modal statistics');assert.deepEqual(errors,[]);
    console.log('Passed: no statistics dialogs or record drawers from home; no business mutations.');
  } finally {await browser.close();}
})().catch(error=>{console.error(error.message);process.exit(1);});
