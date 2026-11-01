const fs=require('node:fs');
const path=require('node:path');
const assert=require('node:assert/strict');
const {randomBytes}=require('node:crypto');
const {chromium}=require(process.env.PLAYWRIGHT_MODULE||'playwright');
const root=path.resolve(__dirname,'..'),out=path.join(root,'.artifacts/results');
let adminPassword='';
(async()=>{
 const env=Object.fromEntries(fs.readFileSync(path.join(root,'.env'),'utf8').split('\n').filter(l=>l&&!l.startsWith('#')).map(l=>{const i=l.indexOf('=');return[l.slice(0,i),l.slice(i+1)];}));
 adminPassword=env.ADMIN_PASSWORD;
 fs.mkdirSync(out,{recursive:true});
 const log=[];const record=s=>{log.push(s);console.log(s);fs.writeFileSync(path.join(out,'scope-browser.log'),log.join('\n')+'\n');};
 const browser=await chromium.launch({headless:true,channel:'chrome'});
 const adminContext=await browser.newContext({viewport:{width:1440,height:1000}}),viewerContext=await browser.newContext({viewport:{width:1440,height:1000}});
 const page=await adminContext.newPage(),viewer=await viewerContext.newPage(),errors=[];
 for(const p of [page,viewer]){p.setDefaultTimeout(20000);p.on('pageerror',e=>errors.push(e.message));}
 const api=async(p,route,method='GET',body)=>p.evaluate(async({route,method,body})=>{const r=await fetch('/api'+route,{method,headers:{'Content-Type':'application/json',Authorization:'Bearer '+sessionStorage.getItem('sg-token')},...(body?{body:JSON.stringify(body)}:{})});return{status:r.status,data:await r.json()};},{route,method,body});
 const login=async(p,email,password)=>{await p.goto('http://127.0.0.1:5180');await p.getByLabel('邮箱').fill(email);await p.getByLabel('密码',{exact:true}).fill(password);await p.getByRole('button',{name:/登\s*录/}).click();await p.getByRole('heading',{name:'工作台',exact:true}).waitFor({timeout:20000});};
 const mark=Date.now(),business='scope-browser-'+mark,name='范围验证用户 '+mark,password=randomBytes(24).toString('base64url');
 let user,allowed,denied;
 try{
  await login(page,env.ADMIN_EMAIL,env.ADMIN_PASSWORD);
  let r=await api(page,'/users','POST',{email:'scope-browser-'+mark+'@test.local',name,password,role:'VIEWER'});assert.equal(r.status,201);user=r.data;
  r=await api(page,'/assets','POST',{hostname:'scope-visible-'+mark,os:'Linux',business});assert.equal(r.status,201);allowed=r.data;
  r=await api(page,'/assets','POST',{hostname:'scope-hidden-'+mark,os:'Linux',business:business+'-denied'});assert.equal(r.status,201);denied=r.data;
  r=await api(page,'/findings/import','POST',{items:[{externalId:'scope-browser-'+mark,assetId:allowed.id,title:'范围证据验证 '+mark,kind:'RISK',severity:'LOW',source:'scope-browser-test',evidence:'SCOPE-BROWSER-PRIVATE-'+mark}]});assert.equal(r.status,201);const finding=r.data.items[0];
  r=await api(page,'/findings/'+finding.id+'/attachments','POST',{name:'scope-fixture.txt',contentType:'text/plain',data:Buffer.from('Scope browser fixture').toString('base64')});assert.equal(r.status,201);const attachment=r.data;
  await page.goto('http://127.0.0.1:5180/#users');
  const search=page.getByPlaceholder('搜索标题、名称或主机');await search.fill(name);await search.press('Enter');
  await page.getByRole('button',{name,exact:true}).click();
  await page.getByRole('button',{name:'设置数据与证据权限',exact:true}).click();
  const dialog=page.getByRole('dialog',{name:'数据访问范围'});
  await dialog.getByLabel('限制资产范围',{exact:true}).click();
  const businesses=dialog.getByLabel('允许的业务名称',{exact:true});await businesses.fill(business);await businesses.press('Enter');
  await dialog.getByLabel('允许读取证据与附件',{exact:true}).click();
  await dialog.getByRole('button',{name:/确\s*定/}).click();await dialog.waitFor({state:'hidden'});
  r=await api(page,'/users/'+user.id);assert.equal(r.data.dataScope.restricted,true);assert.deepEqual(r.data.dataScope.businesses,[business]);assert.equal(r.data.dataScope.canReadEvidence,false);
  record('PASS: administrator ScopeEditor saves one business grant with evidence disabled.');
  await login(viewer,user.email,password);
  await viewer.goto('http://127.0.0.1:5180/#assets');
  await viewer.getByRole('button',{name:allowed.hostname,exact:true}).waitFor();
  assert.equal(await viewer.getByRole('button',{name:denied.hostname,exact:true}).count(),0);
  r=await api(viewer,'/assets');assert.equal(r.data.total,1);assert.equal(r.data.items[0].id,allowed.id);
  assert.equal((await api(viewer,'/assets/'+denied.id)).status,404);
  assert.equal((await api(viewer,'/findings/'+finding.id+'/attachments/'+attachment.id)).status,403);
  r=await api(viewer,'/findings/'+finding.id);assert.equal(r.data.evidence,'[已隐藏]');
  await viewer.goto('http://127.0.0.1:5180/#risks');
  await viewer.getByRole('button',{name:finding.title,exact:true}).click();
  await viewer.getByText('没有读取证据的权限',{exact:true}).first().waitFor();
  assert.ok(!(await viewer.locator('body').innerText()).includes('SCOPE-BROWSER-PRIVATE-'+mark));
  await viewer.getByText('[已隐藏]',{exact:false}).first().waitFor();
  await viewer.getByRole('tabpanel').getByRole('button',{name:finding.title,exact:true}).waitFor();
  await viewer.screenshot({path:path.join(out,'scope-browser.png'),fullPage:true,animations:'disabled'});
  record('PASS: viewer UI shows one authorized asset and redacted evidence; attachment403, direct outside asset404, clear permission error, no secret rendered.');
  const tokenBefore=await viewer.evaluate(()=>sessionStorage.getItem('sg-token'));
  await page.getByRole('button',{name:'设置数据与证据权限',exact:true}).click();
  const editor=page.getByRole('dialog',{name:'数据访问范围'});
  await editor.getByLabel('允许的业务名称',{exact:true}).focus();await editor.getByLabel('允许的业务名称',{exact:true}).press('Backspace');
  await editor.getByRole('button',{name:/确\s*定/}).click();await editor.waitFor({state:'hidden'});
  r=await api(page,'/users/'+user.id);assert.deepEqual(r.data.dataScope.businesses,[]);assert.equal(r.data.dataScope.restricted,true);
  r=await api(viewer,'/auth/me');assert.equal(r.status,200,'Grant changes must apply without invalidating the current session');
  assert.equal(await viewer.evaluate(()=>sessionStorage.getItem('sg-token')),tokenBefore);
  assert.equal((await api(viewer,'/assets')).data.total,0);
  assert.equal((await api(viewer,'/assets/'+allowed.id)).status,404);
  await viewer.reload();await viewer.goto('http://127.0.0.1:5180/#assets');
  await viewer.getByText('暂无记录。可创建记录或接入采集组件。',{exact:true}).waitFor();
  await viewer.screenshot({path:path.join(out,'scope-browser-revoked.png'),fullPage:true,animations:'disabled'});
  record('PASS: administrator revokes all grants in ScopeEditor; existing viewer session stays valid, assets0 and former asset404 without new login.');
  assert.deepEqual(errors,[]);record('PASS: no browser runtime errors.');fs.rmSync(path.join(out,'scope-browser-failure.png'),{force:true});
 }catch(error){await viewer.screenshot({path:path.join(out,'scope-browser-failure.png'),fullPage:true,animations:'disabled'}).catch(()=>{});record('FAIL: '+error.message.split(adminPassword).join('[REDACTED]'));throw error;
 }finally{
  if(user){const cleaned=await api(page,'/users/'+user.id,'PATCH',{disabled:true});assert.equal(cleaned.status,200);}
  for(const asset of [allowed,denied])if(asset){const cleaned=await api(page,'/workflows/assets/'+asset.id+'/archive','POST',{archived:true});assert.equal(cleaned.status,201);}
  record('Cleanup: disabled only the fixture user and archived only the two fixture assets.');
  await browser.close();
 }
})().catch(error=>{console.error(adminPassword?error.message.split(adminPassword).join('[REDACTED]'):error.message);process.exitCode=1;});
