const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict');
const {chromium}=require(process.env.PLAYWRIGHT_MODULE||'playwright');
const root=path.resolve(__dirname,'..'),out=path.join(root,'.artifacts/results');let adminPassword='';
(async()=>{
 const env=Object.fromEntries(fs.readFileSync(path.join(root,'.env'),'utf8').split('\n').filter(l=>l&&!l.startsWith('#')).map(l=>{const i=l.indexOf('=');return[l.slice(0,i),l.slice(i+1)];}));adminPassword=env.ADMIN_PASSWORD;fs.mkdirSync(out,{recursive:true});
 const browser=await chromium.launch({headless:true,channel:'chrome'}),context=await browser.newContext({viewport:{width:1600,height:1150},acceptDownloads:true}),page=await context.newPage(),errors=[];page.setDefaultTimeout(20000);page.on('pageerror',e=>errors.push(e.message));
 try{
  await page.goto('http://127.0.0.1:5180');await page.getByLabel('邮箱').fill(env.ADMIN_EMAIL);await page.getByLabel('密码',{exact:true}).fill(env.ADMIN_PASSWORD);await page.getByRole('button',{name:/登\s*录/}).click();await page.getByRole('heading',{name:'工作台',exact:true}).waitFor();
  await page.goto('http://127.0.0.1:5180/#reports');await page.getByRole('button',{name:'生成筛选报告',exact:true}).waitFor();
  const applied='report-browser-<'+Date.now()+'>',draft='not-applied-'+Date.now();
  await page.route('**/api/record-options/businesses*',route=>{const query=new URL(route.request().url()).searchParams,q=query.get('q')||'',selected=query.get('selected');const items=[applied,draft].filter(name=>selected?name===selected:name.includes(q)).map(name=>({id:name,name,stableId:'owned-report-'+name}));return route.fulfill({json:{items,total:items.length}})});
  async function chooseBusiness(name){await page.getByLabel('业务名称',{exact:true}).fill(name);await page.locator('.ant-select-dropdown:visible .ant-select-item-option').filter({hasText:name}).click()}
  async function chooseDate(label,value){const field=page.getByLabel(label,{exact:true});await field.fill(value);await field.press('Enter')}
  await chooseDate('开始日期（UTC）','2026-10-01');await chooseDate('结束日期（UTC）','2026-10-03');await chooseBusiness(applied);
  const response=page.waitForResponse(r=>r.url().includes('/reports/detailed?')&&r.url().includes('business='));await page.getByRole('button',{name:'生成筛选报告',exact:true}).click();const report=await(await response).json();assert.deepEqual(report.filters,{from:'2026-10-01',to:'2026-10-03',business:applied});
  await page.getByText('已应用：2026-10-01 至 2026-10-03（UTC） · 业务：'+applied,{exact:true}).waitFor();assert.equal(report.totals.assetsCreated,0);
  await chooseBusiness(draft);
  for(const [label,format] of [['下载筛选报告 JSON','json'],['下载筛选报告 CSV','csv'],['下载可打印 HTML','html']]){
   const pending=page.waitForEvent('download');await page.getByRole('button',{name:label,exact:true}).click();const download=await pending;const file=path.join(out,'reports-browser.'+format);await download.saveAs(file);const text=fs.readFileSync(file,'utf8');
   assert.ok(!text.includes(draft));if(format==='json')assert.deepEqual(JSON.parse(text),report);else if(format==='csv'){assert.ok(text.includes(applied));assert.ok(text.includes('2026-10-01'));assert.ok(text.includes('generated_at_utc'));}else{assert.ok(text.includes(applied.replace('<','&lt;').replace('>','&gt;')));assert.ok(!text.includes(applied));assert.ok(text.includes('创建日期趋势'));}
  }
  await page.evaluate(()=>{const original=window.open.bind(window);window.open=(...args)=>{const opened=original(...args);if(opened)opened.print=()=>{opened.__reportPrintCalled=true;};return opened;};});
  const popupPromise=page.waitForEvent('popup');await page.getByRole('button',{name:'打印 / 保存为 PDF',exact:true}).click();const popup=await popupPromise;await popup.waitForLoadState();assert.equal(await popup.evaluate(()=>window.__reportPrintCalled),true);assert.ok((await popup.locator('body').innerText()).includes(applied));assert.ok(!(await popup.locator('body').innerText()).includes(draft));await popup.close();
  await page.screenshot({path:path.join(out,'reports-browser.png'),fullPage:true,animations:'disabled'});assert.deepEqual(errors,[]);
  fs.writeFileSync(path.join(out,'reports-browser.log'),'PASS: UTC/business report generation; exact applied-filter JSON/CSV/HTML downloads despite edited draft; HTML escaping; print window receives same report and invokes browser print; no page errors. No fixture records created.\n');console.log('Reports browser passed: filtered generation, JSON/CSV/HTML exports, escaped printable HTML and print invocation, no runtime errors.');
 }finally{await browser.close();}
})().catch(e=>{const message=adminPassword?e.message.split(adminPassword).join('[REDACTED]'):e.message;fs.mkdirSync(out,{recursive:true});fs.writeFileSync(path.join(out,'reports-browser.log'),'FAIL: '+message+'\n');console.error(message);process.exitCode=1;});
