const fs=require('node:fs'),assert=require('node:assert/strict'),{chromium}=require(process.env.PLAYWRIGHT_MODULE||'playwright');
const {databaseRuleCatalog}=require('../apps/api/dist/data-security');
const env=Object.fromEntries(fs.readFileSync('.env','utf8').split(/\r?\n/).filter(x=>x.includes('=')).map(x=>{const i=x.indexOf('=');return[x.slice(0,i),x.slice(i+1)]}));
async function main(){
 const login=await fetch('http://127.0.0.1:4010/api/auth/login',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({email:env.ADMIN_EMAIL||'admin@selfguard.local',password:env.ADMIN_PASSWORD})});assert.ok(login.ok);const {token}=await login.json();
 const browser=await chromium.launch({headless:true,channel:'chrome'});
 try{for(const width of [1440,390]){
 const page=await browser.newPage({viewport:{width,height:1000}});page.setDefaultTimeout(10000);const errors=[];page.on('pageerror',e=>errors.push(e.message));await page.addInitScript(token=>sessionStorage.setItem('sg-token',token),token);
 const assetId='00000000-0000-4000-8000-000000000123';let created;
 const rule={id:'00000000-0000-4000-8000-000000000124',name:'数据库爆破规则样本',kind:'LOG',severity:'HIGH',config:{type:'DATABASE_AUTH',service:'postgresql',path:'/db/log.json',threshold:5,windowSeconds:60}};
 await page.route('**/api/rule-tools/**',route=>{const path=new URL(route.request().url()).pathname;if(path.endsWith('/catalog/database'))return route.fulfill({json:{items:databaseRuleCatalog,requiredCapability:'data-security-v1'}});return route.fulfill({json:{ruleId:rule.id,name:rule.name,kind:rule.kind,applicability:{},exceptions:[]}})});
 await page.route('**/api/rules**',route=>{if(route.request().method()==='POST'){created=route.request().postDataJSON();return route.fulfill({json:{id:'new',...created}})}return route.fulfill({json:{items:[rule],total:1}})});
 await page.route('**/api/scan-plans/options',route=>route.fulfill({json:{assets:[{id:assetId,hostname:'数据库主机',tags:['db']}],businesses:[]}}));
 await page.goto('http://127.0.0.1:5180/#data-security');await page.getByRole('button',{name:'数据库疑似口令爆破',exact:true}).click();
 let drawer=page.getByRole('dialog',{name:'配置规则 · 数据库疑似口令爆破',exact:true});await drawer.waitFor();assert.equal(await page.locator('.record-inline-editor:visible').count(),0);
 await drawer.getByLabel('日志文件绝对路径',{exact:true}).fill('/db/log.json');
 await drawer.getByLabel('适用资产',{exact:true}).click();await page.locator('.ant-select-dropdown:visible').getByText('数据库主机',{exact:true}).click();await drawer.getByLabel('适用资产',{exact:true}).press('Escape');
 await drawer.getByRole('button',{name:'创建并启用规则',exact:true}).click();await drawer.waitFor({state:'hidden'});assert.equal(created.config.type,'DATABASE_AUTH');assert.deepEqual(created.config.applicability.assetIds,[assetId]);
 await page.getByRole('link',{name:'管理规则适用范围',exact:true}).click();
 const chooser=page.getByRole('combobox',{name:'检测规则',exact:true});await chooser.click();await page.locator('.ant-select-dropdown:visible').getByText(rule.name+' · 日志检测',{exact:true}).click();
 drawer=page.getByRole('dialog',{name:'规则适用范围 · '+rule.name,exact:true});await drawer.waitFor();assert.equal(await page.locator('.ant-drawer-open.ant-drawer-right').count(),1);await drawer.locator('.ant-drawer-close').click();
 const event={id:'trace-event',siteId:assetId,method:'GET',path:'/api/orders',ruleId:'SQLI',action:'BLOCK',remoteIp:'192.0.2.1',timestamp:new Date().toISOString(),context:{requestId:'trace-request',peerIp:'192.0.2.1',clientIp:'192.0.2.1',sourceBasis:'SOCKET_PEER',incomingTls:false,action:'BLOCK',outcome:'BLOCKED_BY_WAF',queryKeys:[],forwarded:false}};
 const access={id:'trace-request',nodeId:'test-node',siteId:assetId,method:'GET',path:'/api/orders',status:403,durationMicros:100,context:event.context,timestamp:event.timestamp};
 await page.route('**/api/waf-events**',route=>route.fulfill({json:new URL(route.request().url()).pathname==='/api/waf-events'?{items:[event],total:1}:event}));
 await page.route('**/api/waf-access/**',route=>route.fulfill({json:access}));
 await page.goto('http://127.0.0.1:5180/#waf-events');await page.locator('.ant-table-tbody .record-title-link').first().click();drawer=page.locator('.ant-drawer-open.ant-drawer-right');await drawer.getByText('完整原始记录',{exact:true}).waitFor();assert.equal(await drawer.locator('.record-fields details').count(),0);
 await drawer.getByRole('button',{name:'查看同一请求的访问结果',exact:true}).click();await drawer.getByText('HTTP 403',{exact:true}).waitFor();await drawer.getByRole('button',{name:'返回攻击记录',exact:true}).click();await drawer.getByText('WAF已阻断本次请求',{exact:true}).waitFor();
 assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1));assert.ok(await drawer.locator('.ant-drawer-body').evaluate(el=>el.scrollWidth<=el.clientWidth+1));assert.deepEqual(errors,[]);
 console.log('PASS database template/scoped creation, rule right drawer, visible raw tables, linked access/back and layout '+width);await page.close();
 }}finally{await browser.close()}
}
main().catch(e=>{console.error(e.stack||e.message);process.exitCode=1});
