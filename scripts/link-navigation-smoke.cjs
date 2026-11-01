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
    function normalColor(value){return value==='rgb(37, 95, 212)'||value==='rgb(28, 79, 182)';}
    async function presentation(selector,disabled=false){
      await page.mouse.move(0,0);
      const styles=await page.locator(selector).evaluateAll(elements=>elements.map(element=>({text:element.textContent,color:getComputedStyle(element).color,weight:getComputedStyle(element).fontWeight})));
      assert.ok(styles.length,'Expected controls for '+selector);
      for(const style of styles){assert.equal(style.weight,disabled?'400':'600',JSON.stringify(style));assert.equal(normalColor(style.color),!disabled,JSON.stringify(style));}
    }
    await page.locator('.workload-health .dash-bar-row').first().waitFor();
    await presentation('.dash-text-action');
    await page.route('**/api/governance/notifications?*',route=>route.fulfill({contentType:'application/json',body:JSON.stringify({items:[{id:'ui-check-finding',title:'严重告警入口检查',resource:'findings',resourceId:'read-only-fixture',readAt:'2026-10-31T00:00:00Z',createdAt:'2026-10-31T00:00:00Z'},{id:'ui-check-task',title:'任务入口检查',resource:'tasks',resourceId:'read-only-fixture',readAt:'2026-10-31T00:00:00Z',createdAt:'2026-10-31T00:00:00Z'}],total:2,unread:0})}));
    await page.goto('http://127.0.0.1:5180/#notifications');
    await page.getByRole('row').filter({hasText:'严重告警入口检查'}).getByRole('button',{name:'查看问题'}).click();
    await page.getByRole('heading',{name:'全部发现',level:1,exact:true}).waitFor();
    await page.goto('http://127.0.0.1:5180/#notifications');
    await page.getByRole('row').filter({hasText:'任务入口检查'}).getByRole('button',{name:'查看任务'}).click();
    await page.getByRole('heading',{name:'修复任务',level:1,exact:true}).waitFor();
    const routes=Object.keys(pageNames);
    for(const width of [1440,768]){
      await page.setViewportSize({width,height:1080});
      if(width===768){const expand=page.getByRole('button',{name:'展开导航',exact:true});await expand.waitFor();await expand.click();await page.getByRole('button',{name:'收起导航',exact:true}).waitFor();}
      for(const route of routes){
        await page.goto('http://127.0.0.1:5180/#'+route);
        await page.getByRole('heading',{name:pageNames[route],level:1,exact:true}).waitFor();
        await page.waitForLoadState('networkidle');
        const selected=page.locator('.sidebar .ant-menu-item-selected');
        assert.equal(await selected.count(),1,'Selected menu count on '+route);
        assert.ok((await selected.getAttribute('data-menu-id')).endsWith('-'+route),'Wrong selected menu on '+route);
        assert.equal(await selected.textContent(),pageNames[route]);
        const links='.page .ant-btn-link:not(:disabled):not(.ant-btn-disabled),.page a.ant-typography[href]:not(.ant-typography-disabled),.page .dash-text-action:not(:disabled):not(.ant-btn-disabled),.page summary,.page .ant-collapse-item:not(.ant-collapse-item-disabled) .ant-collapse-header-text';
        if(await page.locator(links).count())await presentation(links);
        const plain=await page.locator('.module-record-title').evaluateAll(elements=>elements.map(element=>({color:getComputedStyle(element).color,weight:getComputedStyle(element).fontWeight})));
        for(const style of plain){assert.equal(style.weight,'400');assert.equal(style.color,'rgb(32, 43, 64)');}
        const overflow=await page.locator('.page').evaluate(element=>element.scrollWidth-element.clientWidth);assert.ok(overflow<=1,route+' overflow');
      }
      console.log(`Passed link/plain text styles and exact selected menu on ${routes.length} pages at ${width}px.`);
    }
    await page.goto('http://127.0.0.1:5180/#design-system');
    await page.getByRole('heading',{name:'界面规范',level:1,exact:true}).waitFor();
    await presentation('.design-guide .ant-btn-link:disabled,.design-guide .ant-btn-link.ant-btn-disabled,.design-guide a.ant-typography-disabled',true);
    const hash=await page.evaluate(()=>location.hash);
    await page.locator('.design-guide a.ant-btn-disabled').filter({hasText:'不可用跳转'}).evaluate(element=>element.click());
    assert.equal(await page.evaluate(()=>location.hash),hash);
    await page.getByRole('link',{name:'查看资产列表',exact:true}).click();
    await page.getByRole('heading',{name:'资产列表',level:1,exact:true}).waitFor();
    await page.locator('.record-title-link').first().click();
    await page.locator('.record-drawer').waitFor();
    assert.ok((await page.locator('.sidebar .ant-menu-item-selected').getAttribute('data-menu-id')).endsWith('-assets'));
    await page.locator('.record-drawer .ant-drawer-close').click();
    await page.getByRole('button',{name:'收起导航',exact:true}).click();
    await page.goto('http://127.0.0.1:5180/#sources');
    await page.getByRole('button',{name:'查看检测规则',exact:true}).click();
    await page.getByRole('heading',{name:'检测规则',level:1,exact:true}).waitFor();
    assert.equal(await page.locator('.sidebar .ant-menu-submenu-selected>.ant-menu-submenu-title').textContent(),'策略中心');
    assert.deepEqual(errors,[]);
    console.log('Passed notification resource destinations, disabled anchors, list drawer context and cross-module links; no business mutations.');
  } finally {await browser.close();}
})().catch(error=>{console.error(error.message);process.exit(1);});
