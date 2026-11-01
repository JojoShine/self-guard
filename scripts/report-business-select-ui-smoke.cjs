// Business choices are owned UI fixtures. Report generation uses real read-only
// API queries; downloads must retain the applied scope when the draft changes.
const fs=require('node:fs'),assert=require('node:assert/strict'),{chromium}=require(process.env.PLAYWRIGHT_MODULE||'playwright');
const env=Object.fromEntries(fs.readFileSync('.env','utf8').split(/\r?\n/).filter(line=>line.includes('=')).map(line=>{const i=line.indexOf('=');return[line.slice(0,i),line.slice(i+1)]}));
async function main(){
 const login=await fetch('http://127.0.0.1:4010/api/auth/login',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({email:env.ADMIN_EMAIL||'admin@selfguard.local',password:env.ADMIN_PASSWORD})});assert.ok(login.ok);const{token}=await login.json(),browser=await chromium.launch({headless:true,channel:'chrome'});
 try{for(const width of (process.env.REPORT_CHOICE_WIDTHS||'1920,1440,1280,768,390').split(',').map(Number)){
  const page=await browser.newPage({viewport:{width,height:1000},acceptDownloads:true});page.setDefaultTimeout(12000);await page.addInitScript(token=>sessionStorage.setItem('sg-token',token),token);
  const applied='owned-report-choice-<'+width+'>',draft='owned-report-draft-'+width,groups=[applied,draft].map(name=>({id:name,name,stableId:'owned-'+name})),errors=[];page.on('pageerror',error=>errors.push(error.message));
  await page.route('**/api/**',route=>{const request=route.request(),url=new URL(request.url());assert.equal(request.method(),'GET','Reports UI must not mutate real business records');if(url.pathname==='/api/record-options/businesses'){const selected=url.searchParams.get('selected'),q=url.searchParams.get('q')||'',items=groups.filter(row=>selected?row.id===selected:row.name.includes(q));return route.fulfill({json:{items,total:items.length}})}return route.continue()});
  await page.goto('http://127.0.0.1:5180/#reports');const field=page.getByLabel('业务名称',{exact:true});assert.equal(await field.getAttribute('role'),'combobox','Existing business must be selected, not entered as free text');
  async function choose(name){await field.fill(name);await page.locator('.ant-select-dropdown:visible .ant-select-item-option').filter({hasText:name}).click()}
  await choose(applied);const response=page.waitForResponse(response=>{const url=new URL(response.url());return url.pathname==='/api/reports/detailed'&&url.searchParams.get('business')===applied});await page.getByRole('button',{name:'生成筛选报告',exact:true}).click();const result=await response;assert.equal(result.status(),200);const report=await result.json();assert.equal(report.filters.business,applied);assert.equal(report.totals.assetsCreated,0);
  await page.getByRole('region',{name:'已生成报告',exact:true}).getByText('已应用：'+report.filters.from+' 至 '+report.filters.to+'（UTC） · 业务：'+applied,{exact:true}).waitFor();
  await choose(draft);
  for(const [name,extension]of [['下载筛选报告 JSON','json'],['下载筛选报告 CSV','csv'],['下载可打印 HTML','html']]){
   const pending=page.waitForEvent('download');await page.getByRole('button',{name,exact:true}).click();const download=await pending,content=fs.readFileSync(await download.path(),'utf8');assert.ok(!content.includes(draft));if(extension==='json')assert.deepEqual(JSON.parse(content),report);else if(extension==='csv')assert.ok(content.includes(applied));else{assert.ok(content.includes(applied.replace('<','&lt;').replace('>','&gt;')));assert.ok(!content.includes(applied))}
  }
  assert.deepEqual(errors,[]);assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1));console.log('PASS real report business filter, selected scope, frozen JSON/CSV/HTML and viewport '+width);await page.close();
 }}finally{await browser.close()}
}
main().catch(error=>{console.error(error.stack||error.message);process.exitCode=1});
