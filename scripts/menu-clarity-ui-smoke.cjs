const fs=require('node:fs'),assert=require('node:assert/strict'),{chromium}=require(process.env.PLAYWRIGHT_MODULE||'playwright');
const env=Object.fromEntries(fs.readFileSync('.env','utf8').split(/\r?\n/).filter(x=>x.includes('=')).map(x=>{const i=x.indexOf('=');return[x.slice(0,i),x.slice(i+1)]}));
async function main(){
 const response=await fetch('http://127.0.0.1:4010/api/auth/login',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({email:env.ADMIN_EMAIL||'admin@selfguard.local',password:env.ADMIN_PASSWORD})});assert.ok(response.ok);const{token}=await response.json(),browser=await chromium.launch({headless:true,channel:'chrome'});
 try{for(const width of (process.env.MENU_UI_WIDTHS||'1440,390').split(',').map(Number)){
 const page=await browser.newPage({viewport:{width,height:1000}});page.setDefaultTimeout(12000);const errors=[];page.on('pageerror',e=>errors.push(e.message));await page.addInitScript(token=>sessionStorage.setItem('sg-token',token),token);
 const assetId='00000000-0000-4000-8000-000000000083',rule={id:'00000000-0000-4000-8000-000000000084',name:'文件权限检查',kind:'BASELINE',severity:'MEDIUM',config:{type:'FILE_PERMISSION',path:'/authorized/config',mode:'0640'}};
 let scopeReads=0,patches=[],tests=[],created=[],viewer=false;
 await page.route('**/api/auth/me',async route=>{if(viewer)return route.fulfill({json:{id:'reader',name:'受限人员',role:'VIEWER',dataScope:{restricted:true,canReadEvidence:true}}});return route.continue()});
 await page.route('**/api/scan-plans/options',route=>route.fulfill({json:{assets:[{id:assetId,hostname:'测试主机',tags:['prod'],business:'业务甲'}],businesses:[{id:'business',name:'业务甲'}]}}));
 await page.route('**/api/assets**',route=>route.fulfill({json:{items:[{id:assetId,hostname:'测试主机',tags:[]}],total:1}}));
 await page.route('**/api/rules**',route=>{if(route.request().method()==='POST'){created.push(route.request().postDataJSON());return route.fulfill({json:{id:'created',...created.at(-1)}})}return route.fulfill({json:{items:[rule],total:1}})});
 await page.route('**/api/rule-tools/**',route=>{const request=route.request(),path=new URL(request.url()).pathname;
 if(path.endsWith('/catalog/database'))return route.continue();
 if(path.endsWith('/test')){tests.push(request.postDataJSON());return route.fulfill({json:{status:'COMPLETED',matched:true,readOnly:true,evidence:{type:'FILE_PERMISSION',actual:'0666',expected:'0640'}}})}
 if(request.method()==='PATCH'){const body=request.postDataJSON();patches.push(body);rule.config={...rule.config,...body};return route.fulfill({json:rule})}
 scopeReads++;return route.fulfill({json:{name:rule.name,applicability:rule.config.applicability||{},exceptions:[]}})
 });
 await page.route('**/api/incidents**',route=>route.fulfill({json:{items:[],total:0}}));
 await page.route('**/api/waf-events**',route=>route.fulfill({json:{items:[],total:0}}));
 async function selected(label){
 await page.locator('.ant-breadcrumb').getByText(label,{exact:true}).waitFor();
 if(width>=992)await page.locator('.sidebar .ant-menu-item-selected').filter({hasText:label}).waitFor();
 else{
  await page.waitForFunction(()=>Math.abs(document.querySelector('.sidebar').getBoundingClientRect().width-72)<1);
  const group=['事件调查'].includes(label)?'安全中心':label==='攻击记录'?'Web 防护':'策略中心';
  await page.locator('.sidebar .ant-menu-submenu-selected > .ant-menu-submenu-title').filter({hasText:group}).waitFor();
 }
 }
 async function choose(scope,label,text){const control=label==='检测规则'?scope.getByRole('combobox',{name:label,exact:true}):scope.getByLabel(label,{exact:true});await control.click();await page.locator('.ant-select-dropdown:visible').getByText(text,{exact:true}).click();if(await control.getAttribute('aria-expanded')==='true')await control.press('Escape')}
 await page.goto('http://127.0.0.1:5180/#data-security');await page.getByRole('heading',{name:'数据安全规则',exact:true}).waitFor();await selected('数据安全规则');
 assert.equal(await page.getByRole('heading',{name:'选择适用规则',exact:true}).count(),0);assert.equal(await page.getByRole('combobox',{name:'检测规则',exact:true}).count(),0);
 await page.getByRole('button',{name:'数据库疑似口令爆破',exact:true}).click();let drawer=page.getByRole('dialog',{name:'配置规则 · 数据库疑似口令爆破',exact:true});await choose(drawer,'适用资产','测试主机');await drawer.getByLabel('日志文件绝对路径',{exact:true}).fill('/authorized/db.log');await drawer.getByRole('button',{name:'创建并启用规则',exact:true}).click();await drawer.waitFor({state:'hidden'});assert.equal(created.length,1);assert.deepEqual(created[0].config.applicability.assetIds,[assetId]);
 await page.getByRole('link',{name:'管理规则适用范围',exact:true}).click();await selected('规则适用范围');await choose(page,'检测规则','文件权限检查 · 安全基线');drawer=page.getByRole('dialog',{name:'规则适用范围 · 文件权限检查',exact:true});await drawer.waitFor();assert.equal(await drawer.getByRole('button',{name:'运行只读样本测试',exact:true}).count(),0);assert.equal(await drawer.getByRole('heading',{name:'数据安全基础规则',exact:true}).count(),0);
 await choose(drawer,'适用资产','测试主机');await drawer.getByRole('button',{name:'保存适用范围与豁免',exact:true}).click();await page.waitForFunction(()=>!document.querySelector('.ant-drawer-open .ant-btn-loading'));assert.deepEqual(patches[0].applicability.assetIds,[assetId]);assert.equal(tests.length,0);assert.equal(scopeReads,1);await drawer.locator('.ant-drawer-close').click();
 await page.goto('http://127.0.0.1:5180/#rule-test');await selected('规则样本验证');await choose(page,'检测规则','文件权限检查 · 安全基线');drawer=page.getByRole('dialog',{name:'规则样本验证 · 文件权限检查',exact:true});assert.equal(await drawer.getByRole('button',{name:'保存适用范围与豁免',exact:true}).count(),0);assert.equal(scopeReads,1);await choose(drawer,'样本所属资产','测试主机');await drawer.getByLabel('文件权限样本',{exact:true}).fill('0666');await drawer.getByRole('button',{name:'运行只读样本测试',exact:true}).click();await drawer.getByRole('heading',{name:'样本测试结果',exact:true}).waitFor();assert.equal(tests.length,1);assert.equal(tests[0].fixture.mode,'0666');assert.equal(patches.length,1);assert.equal(await page.locator('.ant-drawer-open.ant-drawer-right').count(),1);assert.equal(await page.locator('.record-inline-editor:visible').count(),0);await drawer.locator('.ant-drawer-close').click();
 await page.goto('http://127.0.0.1:5180/#rule-tools?q=legacy');await page.getByRole('heading',{name:'规则适用范围',exact:true}).first().waitFor();await selected('规则适用范围');assert.ok(page.url().includes('#rule-scope?'));
 await page.getByRole('button',{name:'操作指南',exact:true}).click();await page.locator('.operation-guide-page').waitFor();assert.equal(await page.locator('.sidebar').count(),0);for(const name of ['数据安全规则','规则适用范围','规则样本验证','事件调查','攻击记录'])await page.getByRole('heading',{name,exact:true}).waitFor({state:'attached'});assert.equal(await page.getByRole('heading',{name:'规则范围与样本',exact:true}).count(),0);await page.getByRole('link',{name:'前往规则样本验证',exact:true}).click();await page.getByRole('heading',{name:'规则样本验证',exact:true}).first().waitFor();await selected('规则样本验证');await page.goBack();await page.locator('.operation-guide-page').waitFor();await page.getByRole('heading',{name:'规则样本验证',exact:true}).waitFor({state:'attached'});assert.equal(await page.locator('.sidebar').count(),0);
 for(const [route,label] of [['incidents','事件调查'],['waf-events','攻击记录']]){await page.goto('http://127.0.0.1:5180/#'+route);await page.getByRole('heading',{name:label,exact:true}).waitFor();await selected(label)}
 if(width<992){await page.getByRole('button',{name:'展开导航',exact:true}).click();await page.locator('.sidebar .ant-menu-item-selected').filter({hasText:'攻击记录'}).waitFor();await page.getByRole('button',{name:'收起导航',exact:true}).click();await page.waitForFunction(()=>Math.abs(document.querySelector('.sidebar').getBoundingClientRect().width-72)<1)}

 assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1));
 viewer=true;await page.goto('http://127.0.0.1:5180/#data-security');await page.getByText('当前账户无数据安全规则配置权限',{exact:true}).waitFor();assert.equal(await page.getByRole('button',{name:'数据库疑似口令爆破',exact:true}).count(),0);assert.equal(created.length,1);assert.equal(patches.length,1);assert.equal(tests.length,1);assert.deepEqual(errors,[]);
 console.log('PASS distinct creation/scope/sample workflows, request boundaries, menu/breadcrumb selection, legacy alias, guide/back, permissions and layout '+width);await page.close();
 }}finally{await browser.close()}
}
main().catch(e=>{console.error(e.stack||e.message);process.exitCode=1});
