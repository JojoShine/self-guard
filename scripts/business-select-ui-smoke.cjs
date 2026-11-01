// Every business/asset response and write below belongs to this UI fixture.
const fs=require('node:fs'),assert=require('node:assert/strict'),{chromium}=require(process.env.PLAYWRIGHT_MODULE||'playwright');
const env=Object.fromEntries(fs.readFileSync('.env','utf8').split(/\r?\n/).filter(line=>line.includes('=')).map(line=>{const i=line.indexOf('=');return[line.slice(0,i),line.slice(i+1)]}));
async function main(){
 const login=await fetch('http://127.0.0.1:4010/api/auth/login',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({email:env.ADMIN_EMAIL||'admin@selfguard.local',password:env.ADMIN_PASSWORD})});assert.ok(login.ok);const{token}=await login.json(),browser=await chromium.launch({headless:true,channel:'chrome'});
 try{for(const width of (process.env.BUSINESS_SELECT_WIDTHS||'1920,1440,1280,768,390').split(',').map(Number)){
  const page=await browser.newPage({viewport:{width,height:1000}});page.setDefaultTimeout(12000);await page.addInitScript(token=>sessionStorage.setItem('sg-token',token),token);
  const row={id:'owned-business-asset',hostname:'业务归属验收主机',os:'linux',business:'支付服务',tags:[]},groups=[{id:'支付服务',name:'支付服务',stableId:'owned-payments'},{id:'订单服务',name:'订单服务',stableId:'owned-orders'}],writes=[];let failCreate=true,scoped=false;
  await page.route('**/api/**',async route=>{
   const request=route.request(),url=new URL(request.url()),path=url.pathname;
   if(path==='/api/record-options/businesses'&&request.method()==='POST'){
    const body=request.postDataJSON();assert.deepEqual(body,{name:'新业务验收'});writes.push({kind:'create',body});
    if(failCreate){failCreate=false;return route.fulfill({status:503,json:{message:'夹具：业务登记暂时不可用'}})}
    const result={id:body.name,name:body.name,stableId:'owned-new-business'};groups.push(result);return route.fulfill({json:result});
   }
   if(path==='/api/assets/'+row.id&&request.method()==='PATCH'){const body=request.postDataJSON();writes.push({kind:'asset',body});Object.assign(row,body);return route.fulfill({json:row})}
   assert.equal(request.method(),'GET','Unexpected mutation outside owned business UI fixture');
   if(path==='/api/auth/me'&&scoped)return route.fulfill({json:{id:'owned-scoped-operator',name:'范围受限分析员',role:'ANALYST',dataScope:{restricted:true,businesses:['支付服务'],assetIds:[row.id],canReadEvidence:true}}});
   if(path==='/api/record-options/businesses'){
    const selected=url.searchParams.get('selected'),q=url.searchParams.get('q')||'',items=groups.filter(group=>(!scoped||group.name==='支付服务')&&(selected?group.id===selected:group.name.includes(q)));return route.fulfill({json:{items,total:items.length}});
   }
   if(path==='/api/assets')return route.fulfill({json:{items:[row],total:1}});
   if(path==='/api/assets/'+row.id)return route.fulfill({json:row});
   if(path.startsWith('/api/assets/'+row.id+'/')||path==='/api/asset-changes')return route.fulfill({json:{items:[],total:0}});
   return route.continue();
  });
  await page.goto('http://127.0.0.1:5180/#assets');await page.getByRole('button',{name:row.hostname,exact:true}).click();const drawer=page.locator('.ant-drawer-content:visible');
  await drawer.getByRole('button',{name:'编辑配置',exact:true}).click();const form=drawer.getByRole('region',{name:'编辑记录',exact:true});
  const business=form.getByLabel('所属业务',{exact:true});await form.locator('.business-select').getByText('支付服务',{exact:true}).waitFor();await form.locator('.business-select .ant-select-selector').click();await page.locator('.ant-select-dropdown:visible .ant-select-item-option').filter({hasText:'订单服务'}).click();
  await form.getByRole('button',{name:'创建业务分组',exact:true}).click();const editor=form.getByRole('region',{name:'创建业务分组',exact:true});await editor.getByLabel('新业务名称',{exact:true}).fill(' 新业务验收 ');
  await editor.getByRole('button',{name:'创建并选择业务',exact:true}).click();await editor.getByText('夹具：业务登记暂时不可用',{exact:true}).waitFor();assert.equal(await editor.getByLabel('新业务名称',{exact:true}).inputValue(),' 新业务验收 ');
  assert.equal(await page.locator('.ant-modal-content:visible').count(),0,'Business creation must stay in the current inline form');assert.equal(writes.filter(write=>write.kind==='asset').length,0);
  if(process.env.BUSINESS_SELECT_DEBUG)console.log((await form.ariaSnapshot()).slice(-7000));
  await editor.getByRole('button',{name:'创建并选择业务',exact:true}).click();await editor.waitFor({state:'hidden'});await form.locator('.business-select').getByText('新业务验收',{exact:true}).waitFor();
  await form.getByRole('button',{name:/^保\s*存$/}).click();await form.waitFor({state:'hidden'});assert.equal(row.business,'新业务验收');assert.equal(writes.filter(write=>write.kind==='asset').length,1);
  await drawer.waitFor({state:'hidden'});await page.getByRole('button',{name:row.hostname,exact:true}).click();await drawer.getByRole('button',{name:'编辑配置',exact:true}).click();await form.locator('.business-select').getByText('新业务验收',{exact:true}).waitFor();await form.locator('.business-select .ant-select-clear').click({force:true});await form.getByRole('button',{name:/^保\s*存$/}).click();await form.waitFor({state:'hidden'});assert.equal(row.business,null);assert.equal(writes.filter(write=>write.kind==='asset').at(-1).body.business,null);
  assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1));assert.equal(new URL(page.url()).hash.split('?')[0],'#assets');
  scoped=true;row.business='支付服务';await page.reload();await page.getByRole('button',{name:row.hostname,exact:true}).click();await drawer.getByRole('button',{name:'编辑配置',exact:true}).click();await form.locator('.business-select').getByText('支付服务',{exact:true}).waitFor();assert.equal(await form.getByRole('button',{name:'创建业务分组',exact:true}).count(),0);await form.locator('.business-select .ant-select-selector').click();await page.locator('.ant-select-dropdown:visible .ant-select-item-option').filter({hasText:'支付服务'}).waitFor();assert.equal(await page.locator('.ant-select-dropdown:visible .ant-select-item-option').filter({hasText:'订单服务'}).count(),0);
  console.log('PASS selected business, inline create/retry, stable names, explicit clear, scoped UI and viewport '+width);await page.close();
 }}finally{await browser.close()}
}
main().catch(error=>{console.error(error.stack||error.message);process.exitCode=1});
