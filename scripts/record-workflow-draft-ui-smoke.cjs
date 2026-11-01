// UI-only owned records: navigation between related findings must not carry an
// unsaved disposition draft to the next record. Mutations are forbidden here.
const fs=require('node:fs'),assert=require('node:assert/strict'),{chromium}=require(process.env.PLAYWRIGHT_MODULE||'playwright');
const env=Object.fromEntries(fs.readFileSync('.env','utf8').split(/\r?\n/).filter(line=>line.includes('=')).map(line=>{const i=line.indexOf('=');return[line.slice(0,i),line.slice(i+1)]}));
async function main(){
 const response=await fetch('http://127.0.0.1:4010/api/auth/login',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({email:env.ADMIN_EMAIL||'admin@selfguard.local',password:env.ADMIN_PASSWORD})});assert.ok(response.ok);const{token}=await response.json(),browser=await chromium.launch({headless:true,channel:'chrome'});
 try{for(const width of(process.env.WORKFLOW_DRAFT_WIDTHS||'1920,1440,1280,768,390').split(',').map(Number)){
  const page=await browser.newPage({viewport:{width,height:1000}});page.setDefaultTimeout(15000);const errors=[];page.on('pageerror',error=>errors.push(error.message));await page.addInitScript(token=>sessionStorage.setItem('sg-token',token),token);
  const rows=['A','B'].map(label=>({id:'owned-workflow-draft-'+label,title:'受控未保存研判 '+label,kind:'RISK',source:'fixture',severity:'HIGH',status:'OPEN',evidence:'受控风险依据 '+label}));
  await page.route('**/api/**',async route=>{
   const request=route.request(),url=new URL(request.url()),pathname=url.pathname;assert.equal(request.method(),'GET','This draft navigation fixture must never mutate a record');
   if(pathname==='/api/findings')return route.fulfill({json:{items:rows,total:2}});
   const detail=rows.find(row=>pathname==='/api/findings/'+row.id);if(detail)return route.fulfill({json:detail});
   if(rows.some(row=>pathname==='/api/workflows/findings/'+row.id+'/context'))return route.fulfill({json:{resource:'findings',total:2,evidence:{assets:[],findings:rows,network:{relations:[],missing:[]}}}});
   if(rows.some(row=>pathname.startsWith('/api/findings/'+row.id+'/'))||pathname==='/api/audit')return route.fulfill({json:{items:[],total:0}});
   return route.continue();
  });
  await page.goto('http://127.0.0.1:5180/#risks');await page.getByRole('button',{name:rows[0].title,exact:true}).click();const drawer=page.locator('.ant-drawer-content:visible');await drawer.getByRole('button',{name:'问题研判',exact:true}).click();const editor=drawer.getByRole('region',{name:'问题研判',exact:true});await editor.getByLabel('延期原因',{exact:true}).fill('只属于A的未保存原因');
  await drawer.locator('.security-context-finding').getByRole('button',{name:rows[1].title,exact:true}).click();await page.waitForFunction(title=>document.querySelector('.ant-drawer-title')?.textContent===title,rows[1].title);assert.equal(await editor.count(),0,'The prior finding draft must close when opening a different finding');
  await drawer.getByRole('button',{name:'问题研判',exact:true}).click();assert.equal(await drawer.getByLabel('延期原因',{exact:true}).inputValue(),'');assert.equal(new URL(page.url()).hash.split('?')[0],'#risks');await page.locator('.ant-breadcrumb').getByText('风险管理',{exact:true}).waitFor();assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1));assert.deepEqual(errors,[]);assert.equal(await page.locator('.ant-modal:visible').count(),0);console.log('PASS related-finding navigation clears old draft, keeps menu and no second modal at '+width);await page.close();
 }}finally{await browser.close()}
}
main().catch(error=>{console.error(error.stack||error.message);process.exitCode=1});
