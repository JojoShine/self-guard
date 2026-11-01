// Hold an intercepted mutation, change page, then check the actual refresh URL.
const fs=require('node:fs'),assert=require('node:assert/strict'),{chromium}=require(process.env.PLAYWRIGHT_MODULE||'playwright');
const env=Object.fromEntries(fs.readFileSync('.env','utf8').split(/\r?\n/).filter(s=>s.includes('=')).map(s=>{const i=s.indexOf('=');return[s.slice(0,i),s.slice(i+1)]}));
async function main(){
 const login=await fetch('http://127.0.0.1:4010/api/auth/login',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({email:env.ADMIN_EMAIL||'admin@selfguard.local',password:env.ADMIN_PASSWORD})});assert.ok(login.ok);const{token}=await login.json(),browser=await chromium.launch({headless:true,channel:'chrome'});
 try{for(const kind of ['release','ssh']){
  const page=await browser.newPage({viewport:{width:1440,height:1000}});page.setDefaultTimeout(10000);await page.addInitScript(token=>sessionStorage.setItem('sg-token',token),token);
  const endpoint=kind==='release'?'agent-releases':'agent-install-batches',action=kind==='release'?'publish':'start';let finish,start;const pending=new Promise(resolve=>{finish=resolve}),started=new Promise(resolve=>{start=resolve});
  const rows=Array.from({length:16},(_,index)=>({id:'00000000-0000-4000-8000-'+String(index+100).padStart(12,'0'),name:'Owned page '+(index+1),version:'0.4.1-fixture.'+(index+1),architecture:'arm64',channel:'canary',status:'DRAFT',sha256:'a'.repeat(64),size:100,sequence:index+100,expiresAt:new Date(Date.now()+86400000).toISOString(),createdAt:new Date().toISOString(),concurrency:5,targets:[{id:'target-'+index,assetId:'asset-'+index,address:'192.0.2.'+(index+1),status:'WAITING',attempts:0}]}));
  await page.route('**/api/agent-installations**',route=>route.fulfill({json:{items:[],total:0}}));
  await page.route('**/api/'+endpoint+'**',async route=>{const request=route.request(),url=new URL(request.url());if(request.method()==='GET'){const number=Number(url.searchParams.get('page')||1);return route.fulfill({json:{items:number===1?rows.slice(0,15):rows.slice(15),total:16,trustRoot:Buffer.alloc(32).toString('base64')}});}assert.equal(url.pathname,'/api/'+endpoint+'/'+rows[0].id+'/'+action);start();await pending;rows[0].status=kind==='release'?'PUBLISHED':'RUNNING';return route.fulfill({json:rows[0]});});
  try{
   await page.goto('http://127.0.0.1:5180/#enroll');await page.waitForFunction(()=>(document.querySelector('.account-name')?.textContent||'').trim().length>1,{},{timeout:30000});await page.locator('.sidebar').evaluate(async element=>{await Promise.all(element.getAnimations().map(animation=>animation.finished.catch(()=>{})));});
   const tab=page.getByRole('tab',{name:kind==='release'?'可用发行版本':'SSH 批量安装',exact:true});await tab.click();await page.getByRole('row').filter({has:page.getByText(kind==='release'?rows[0].version+' · arm64':rows[0].name,{exact:true})}).getByRole('button',{name:kind==='release'?'发布':'确认并开始',exact:true}).click();
   const review=page.getByRole('region',{name:kind==='release'?'发布发行版本确认':'确认批量安装目标',exact:true});await review.getByRole('button',{name:kind==='release'?'确认发布版本':'确认并开始',exact:true}).click();await started;
   await page.locator('.ant-pagination-item-2').click();await page.getByText(kind==='release'?rows[15].version+' · arm64':rows[15].name,{exact:true}).waitFor();
   const refreshed=page.waitForResponse(response=>new URL(response.url()).pathname==='/api/'+endpoint&&response.request().method()==='GET');finish();const response=await refreshed;assert.equal(new URL(response.url()).searchParams.get('page'),'2','Mutation completion must refresh the current page');await page.getByText(kind==='release'?rows[15].version+' · arm64':rows[15].name,{exact:true}).waitFor();assert.ok((await page.locator('.ant-pagination-item-2').getAttribute('class')).includes('active'));console.log('PASS '+kind+' delayed mutation refreshes current page2 without stale page1 rows');
  }finally{finish();await page.close()}
 }}finally{await browser.close()}
}
main().catch(error=>{console.error(error.stack||error.message);process.exitCode=1});
