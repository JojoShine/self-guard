// Owned UI fixtures only: delayed child-editor responses must not replace a
// different record opened after navigation. No real asset is archived/assigned.
const fs=require('node:fs'),assert=require('node:assert/strict'),{chromium}=require(process.env.PLAYWRIGHT_MODULE||'playwright');
const env=Object.fromEntries(fs.readFileSync('.env','utf8').split(/\r?\n/).filter(line=>line.includes('=')).map(line=>{const i=line.indexOf('=');return[line.slice(0,i),line.slice(i+1)]}));
async function main(){
 const login=await fetch('http://127.0.0.1:4010/api/auth/login',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({email:env.ADMIN_EMAIL||'admin@selfguard.local',password:env.ADMIN_PASSWORD})});assert.ok(login.ok);const{token}=await login.json(),browser=await chromium.launch({headless:true,channel:'chrome'});
 try{for(const width of (process.env.LATE_CHILD_WIDTHS||'1920,1440,1280,768,390').split(',').map(Number))for(const kind of (process.env.LATE_CHILD_KINDS||'archive,assign,comment').split(',')){
  const page=await browser.newPage({viewport:{width,height:1000}});page.setDefaultTimeout(10000);await page.addInitScript(token=>sessionStorage.setItem('sg-token',token),token);
  const asset={id:'owned-late-asset',hostname:'迟到归档验收主机',os:'linux',tags:[],archivedAt:null},risk={id:'owned-late-risk',title:'迟到分派验收风险',kind:'RISK',source:'fixture',severity:'HIGH',status:'OPEN',assetId:asset.id,evidence:'受控风险证据'},site={id:'owned-late-site',name:'保持选中的验收站点',hostname:'late.fixture.test',upstream:'http://127.0.0.1:8080',mode:'OBSERVE',enabled:true,config:{},version:1};let release,commentReads=0;
  const path=kind==='archive'?'/api/workflows/assets/'+asset.id+'/archive':kind==='comment'?'/api/assets/'+asset.id+'/comments':'/api/findings/'+risk.id;
  await page.route('**/api/**',async route=>{
   const request=route.request(),url=new URL(request.url()),pathname=url.pathname;
   if(pathname===path&&request.method()!=='GET'){
    assert.equal(request.method(),kind==='assign'?'PATCH':'POST');const body=request.postDataJSON();assert.deepEqual(body,kind==='archive'?{archived:true}:kind==='comment'?{body:'受控旧记录备注'}:{owner:'owned-new-operator'});await new Promise(resolve=>{release=resolve});if(kind==='archive')asset.archivedAt=new Date().toISOString();else if(kind==='assign')risk.owner=body.owner;return route.fulfill({json:kind==='archive'?asset:kind==='comment'?{id:'owned-comment',body:body.body}:risk});
   }
   assert.equal(request.method(),'GET','Unexpected mutation outside owned late-child fixture');if(pathname==='/api/assets/'+asset.id+'/comments')commentReads++;
   const resources={assets:[asset],findings:[risk],sites:[site]},parts=pathname.split('/').filter(Boolean),records=resources[parts[1]];
   if(records&&parts.length===2)return route.fulfill({json:{items:records,total:records.length}});
   if(records&&parts.length===3){const row=records.find(row=>row.id===parts[2]);if(row)return route.fulfill({json:row})}
   if(pathname==='/api/workflows/findings/'+risk.id+'/context')return route.fulfill({json:{resource:'findings',id:risk.id,total:1,evidence:{assets:[asset],findings:[risk],network:{relations:[],missing:[]}}}});
   if((records&&parts[2]?.startsWith('owned-late-'))||pathname==='/api/audit'||pathname==='/api/asset-changes')return route.fulfill({json:{items:[],total:0}});
   return route.continue();
  });
  await page.goto('http://127.0.0.1:5180/#'+(kind==='assign'?'risks':'assets'));if(kind==='archive'){await page.getByRole('button',{name:'更多操作',exact:true}).click();await page.getByRole('menuitem',{name:'归档资产',exact:true}).click()}else await page.getByRole('button',{name:kind==='assign'?risk.title:asset.hostname,exact:true}).click();const drawer=page.locator('.ant-drawer-open .ant-drawer-content');await page.waitForLoadState('networkidle');
  if(kind==='archive'){await drawer.getByRole('button',{name:'确认归档资产',exact:true}).click()}
  else if(kind==='comment'){assert.equal(commentReads,1,'Original comments must have loaded before the held submission');await drawer.getByLabel('处理备注',{exact:true}).fill('受控旧记录备注');await drawer.getByRole('button',{name:'添加备注',exact:true}).click()}
  else{await drawer.getByRole('button',{name:'分派负责人',exact:true}).click();await drawer.getByLabel('负责人',{exact:true}).fill('owned-new-operator');await drawer.getByRole('button',{name:'保存处置',exact:true}).click()}
  if(kind!=='archive')await page.locator('.ant-drawer-close').click();await page.goto('http://127.0.0.1:5180/#sites');await page.getByRole('button',{name:site.name,exact:true}).click();assert.ok(release);const completed=page.waitForResponse(response=>new URL(response.url()).pathname===path&&response.request().method()!=='GET');release();await completed;
  await page.waitForLoadState('networkidle');if(kind==='comment')assert.equal(commentReads,1,'Late comment completion must not reload old record data after leaving it');assert.equal(await page.locator('.ant-drawer-title').innerText(),site.name);assert.equal(new URL(page.url()).hash.split('?')[0],'#sites');await page.getByRole('button',{name:site.name,exact:true}).waitFor();assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1));console.log('PASS delayed '+kind+' cannot replace new detail/menu at '+width);await page.close();
 }}finally{await browser.close()}
}
main().catch(error=>{console.error(error.stack||error.message);process.exitCode=1});
