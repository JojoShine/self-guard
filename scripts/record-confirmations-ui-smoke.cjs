// Only the explicit UI fixture routes may mutate; no real task is approved or restored.
const fs=require('node:fs'),assert=require('node:assert/strict'),{chromium}=require(process.env.PLAYWRIGHT_MODULE||'playwright');
const env=Object.fromEntries(fs.readFileSync('.env','utf8').split(/\r?\n/).filter(line=>line.includes('=')).map(line=>{const index=line.indexOf('=');return[line.slice(0,index),line.slice(index+1)]}));
async function main(){
 const response=await fetch('http://127.0.0.1:4010/api/auth/login',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({email:env.ADMIN_EMAIL||'admin@selfguard.local',password:env.ADMIN_PASSWORD})});assert.ok(response.ok);const{token}=await response.json();
 const browser=await chromium.launch({headless:true,channel:'chrome'});
 try{for(const width of (process.env.INLINE_ACTION_UI_WIDTHS||'1920,1440,1280,768,390').split(',').map(Number)){
  const page=await browser.newPage({viewport:{width,height:1000}});page.setDefaultTimeout(10000);await page.addInitScript(token=>sessionStorage.setItem('sg-token',token),token);
  const pending={id:'owned-confirm-pending',title:'内联审批验收任务',status:'PENDING',template:'FILE_PERMISSION',params:{path:'/owned/fixture',permission:'0640'},assetId:null,version:1},completed={...pending,id:'owned-confirm-complete',title:'内联回滚验收任务',status:'SUCCEEDED'},site={id:'owned-confirm-site',name:'内联版本验收站点',hostname:'owned.fixture.test',upstream:'http://127.0.0.1:8080',mode:'OBSERVE',enabled:true,version:2,config:{}};
  let failApprove=true,approvals=0,rollbacks=0,restores=0,holdApproval=false,releaseApproval;
  await page.route('**/api/**',async route=>{
   const request=route.request(),url=new URL(request.url()),path=url.pathname;
   if(request.method()==='POST'&&path==='/api/tasks/'+pending.id+'/approve'){approvals++;assert.deepEqual(request.postDataJSON(),{});if(failApprove){failApprove=false;return route.fulfill({status:409,json:{message:'夹具：当前任务需要重新核对'}})}if(holdApproval)await new Promise(resolve=>{releaseApproval=resolve});pending.status='APPROVED';return route.fulfill({json:pending})}
   if(request.method()==='POST'&&path==='/api/repair/'+completed.id+'/rollback'){rollbacks++;return route.fulfill({json:{id:'owned-rollback-draft',status:'PENDING'}})}
   if(request.method()==='POST'&&path==='/api/sites/'+site.id+'/restore'){restores++;assert.deepEqual(request.postDataJSON(),{version:1});site.version=3;return route.fulfill({json:site})}
   assert.equal(request.method(),'GET','Unexpected mutation outside owned fixture');
   if(path==='/api/tasks')return route.fulfill({json:{items:[pending,completed],total:2}});
   if(path==='/api/tasks/'+pending.id)return route.fulfill({json:pending});if(path==='/api/tasks/'+completed.id)return route.fulfill({json:completed});
   if(path==='/api/sites')return route.fulfill({json:{items:[site],total:1}});if(path==='/api/sites/'+site.id)return route.fulfill({json:site});
   if(path==='/api/sites/'+site.id+'/versions')return route.fulfill({json:{items:[{id:'owned-version-1',version:1,actor:'fixture',createdAt:'2026-10-31T00:00:00Z',snapshot:{config:{},enabled:true,mode:'OBSERVE'}}],total:1}});
   if(path.startsWith('/api/tasks/owned-confirm-')||path.startsWith('/api/sites/owned-confirm-')||path==='/api/audit')return route.fulfill({json:{items:[],total:0}});
   return route.continue();
  });
  await page.goto('http://127.0.0.1:5180/#tasks');await page.getByRole('button',{name:pending.title,exact:true}).click();let drawer=page.locator('.ant-drawer-content:visible');
  await drawer.getByRole('button',{name:/^批\s*准$/}).click();let region=drawer.getByRole('region',{name:'批准受控文件变更',exact:true});await region.waitFor();assert.equal(approvals,0);assert.equal(await page.locator('.ant-modal-wrap:visible').count(),0);
  await region.getByRole('button',{name:'确认批准',exact:true}).click();await region.getByText('夹具：当前任务需要重新核对',{exact:true}).waitFor();assert.equal(approvals,1);
  await region.getByRole('button',{name:'确认批准',exact:true}).click();await region.waitFor({state:'hidden'});assert.equal(approvals,2);assert.equal(await page.locator('.ant-drawer-content:visible').count(),1);
  await page.locator('.ant-drawer-close').click();await page.getByRole('button',{name:completed.title,exact:true}).click();drawer=page.locator('.ant-drawer-content:visible');
  await drawer.getByRole('button',{name:'申请回滚',exact:true}).click();region=drawer.getByRole('region',{name:'创建回滚任务',exact:true});await region.waitFor();assert.equal(rollbacks,0);await region.getByText(/任务仍需审批/).waitFor();
  await region.getByRole('button',{name:'确认创建回滚申请',exact:true}).click();await region.waitFor({state:'hidden'});assert.equal(rollbacks,1);assert.equal(await page.locator('.ant-modal-wrap:visible').count(),0);
  await page.goto('http://127.0.0.1:5180/#sites');await page.getByRole('button',{name:site.name,exact:true}).click();drawer=page.locator('.ant-drawer-content:visible');
  await drawer.getByRole('button',{name:'恢复为新版本',exact:true}).click();region=drawer.getByRole('region',{name:'恢复版本 1',exact:true});await region.waitFor();assert.equal(restores,0);await region.getByRole('button',{name:'确认恢复为新版本',exact:true}).click();await region.waitFor({state:'hidden'});assert.equal(restores,1);
  assert.equal(await page.locator('.ant-modal-wrap:visible').count(),0);assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1));
  pending.status='PENDING';holdApproval=true;await page.goto('http://127.0.0.1:5180/#tasks');await page.getByRole('button',{name:pending.title,exact:true}).click();drawer=page.locator('.ant-drawer-content:visible');await drawer.getByRole('button',{name:'批准',exact:true}).click();const nextApproval=page.waitForRequest(r=>r.url().endsWith('/tasks/'+pending.id+'/approve')&&r.method()==='POST');await drawer.getByRole('button',{name:'确认批准',exact:true}).click();await nextApproval;await page.locator('.ant-drawer-close').click();await page.goto('http://127.0.0.1:5180/#sites');await page.getByRole('button',{name:site.name,exact:true}).click();assert.ok(releaseApproval);releaseApproval();await page.getByText('任务已批准，等待 Agent 领取',{exact:true}).waitFor();await page.waitForTimeout(300);assert.equal(await page.locator('.ant-drawer-title').innerText(),site.name);await page.getByRole('button',{name:site.name,exact:true}).waitFor();
  console.log('PASS inline approval retry, rollback, historical restore, late action cannot replace new detail/menu data and viewport '+width);await page.close();
 }}finally{await browser.close()}
}
main().catch(error=>{console.error(error.stack||error.message);process.exitCode=1});
