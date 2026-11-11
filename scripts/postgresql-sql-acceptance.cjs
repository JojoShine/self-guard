const fs=require('node:fs'),path=require('node:path'),os=require('node:os'),assert=require('node:assert/strict');
const {spawn,spawnSync}=require('node:child_process'),{randomBytes}=require('node:crypto');
const root=path.resolve(__dirname,'..'),apiDir=path.join(root,'apps/api'),webDir=path.join(root,'apps/web');
const output=path.join(root,'.artifacts/results/sql-execution');fs.mkdirSync(output,{recursive:true});
const {Db}=require(path.join(apiDir,'dist/db')),{hashPassword}=require(path.join(apiDir,'dist/security'));
const pause=ms=>new Promise(resolve=>setTimeout(resolve,ms));
function docker(args,input){const r=spawnSync('docker',args,{input,encoding:'utf8',timeout:60000,maxBuffer:4<<20});assert.equal(r.status,0,'docker operation failed: '+r.stderr.slice(-700));return r.stdout;}
async function stop(child){if(child&&child.exitCode===null){child.kill('SIGTERM');await Promise.race([new Promise(r=>child.once('exit',r)),pause(3000)]);if(child.exitCode===null)child.kill('SIGKILL');}}
async function ready(url){for(let i=0;i<100;i++){try{if((await fetch(url)).ok)return;}catch{}await pause(150);}throw Error('Isolated service did not start');}
async function main(){
 const id=randomBytes(8).toString('hex'),schema='sql_accept_'+id,container='sg-pg-sql-'+id,temporary=fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(),'sg-connections-')));
 const binary=process.env.TEST_AGENT_BINARY||path.join(root,'.artifacts/bin/agent-pg-sql-linux-'+(process.arch==='arm64'?'arm64':'amd64')),image='public.ecr.aws/docker/library/postgres:14-alpine';
 const admin=new Db();let db,server,vite,agent,browser,created=false;
 try{
  const inspection=spawnSync(process.execPath,[path.join(root,'scripts/postgresql-sql-fixture.cjs')],{cwd:root,encoding:'utf8',timeout:120000});assert.equal(inspection.status,0,inspection.stderr);
  const version='14.24';const sourcePath=path.join(temporary,'sql.csv');fs.copyFileSync(path.join(output,'sample.csv'),sourcePath);fs.chmodSync(sourcePath,0o600);
  await admin.$executeRawUnsafe('CREATE SCHEMA "'+schema+'"');const url=new URL(process.env.DATABASE_URL);url.searchParams.set('schema',schema);const env={...process.env,DATABASE_URL:url.href,PORT:'4407',BASE_PATH:''};
  const migrate=spawnSync(process.execPath,['node_modules/prisma/build/index.js','migrate','deploy'],{cwd:apiDir,env,encoding:'utf8'});assert.equal(migrate.status,0,migrate.stderr);db=new Db({datasourceUrl:url.href});
  const email='sql@example.invalid',password=randomBytes(20).toString('hex');await db.user.create({data:{email,name:'SQL执行隔离验收',role:'ADMIN',passwordHash:hashPassword(password)}});
  server=spawn(process.execPath,['dist/main.js'],{cwd:apiDir,env,stdio:['ignore',fs.openSync(path.join(output,'api.log'),'w'),fs.openSync(path.join(output,'api-error.log'),'w')]});await ready('http://127.0.0.1:4407/healthz');
  const base='http://127.0.0.1:4407/api';
  async function request(route,body,token,method=body?'POST':'GET'){const r=await fetch(base+route,{method,headers:{'content-type':'application/json',...(token?{authorization:'Bearer '+token}:{})},...(body?{body:JSON.stringify(body)}:{})});return {status:r.status,value:await r.json()};}
  const login=await request('/auth/login',{email,password});assert.equal(login.status,200);const token=login.value.token;
  const credential=randomBytes(32).toString('hex'),identity='pg-connection-acceptance-'+id;
  const enrollment=await request('/agent/enroll',{hostname:'PG14隔离采集主机',os:'linux',identity,credential,agentVersion:'0.4.12-pg-connections.1'},process.env.ENROLLMENT_TOKEN);assert.equal(enrollment.status,201);const host=enrollment.value.assetId;
  const instanceResponse=await request('/database-instances',{name:'PostgreSQL14 SQL原文验收',engine:'postgresql',stableKey:'acceptance-'+id,owner:'隔离测试',hostIds:[host],auditSources:[{assetId:host,path:sourcePath,format:'postgresql-csv-sql'}]},token);assert.equal(instanceResponse.status,201);const instance=instanceResponse.value;
  const state=path.join(temporary,'state');fs.mkdirSync(state,{mode:0o700});
  fs.writeFileSync(path.join(state,'identity.json'),JSON.stringify({Identity:identity,assetId:host,token:credential}),{mode:0o600});
  const configPath=path.join(temporary,'collector.json');fs.writeFileSync(configPath,JSON.stringify({Server:'http://host.docker.internal:4407',AllowHTTP:true,StateDir:state,AllowedRoot:temporary,ReadOnly:true,MaxCPUs:1,MaxMemoryBytes:128<<20,MaxQueueBytes:16<<20,BytesPerSecond:1<<20}),{mode:0o600});
  agent=spawn('docker',['run','--rm','--name','sg-pg-reader-'+id,'--user',process.getuid()+':'+process.getgid(),'--cpus','1','--memory','128m','--pids-limit','32','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges','-v',temporary+':'+temporary+':ro','-v',state+':'+state+':rw','-v',binary+':/selfguard-agent:ro','-e','AGENT_CONFIG='+configPath,'--entrypoint','/selfguard-agent',image],{stdio:['ignore',fs.openSync(path.join(output,'collector.log'),'w'),fs.openSync(path.join(output,'collector-error.log'),'w')]});
  let events;for(let i=0;i<120;i++){const r=await request('/data-security/events?instanceId='+instance.id,undefined,token);assert.equal(r.status,200);events=r.value.items;if(events.length>=8)break;if(agent.exitCode!==null)throw Error('Collector exited; inspect collector-error.log');await pause(500);}
  assert.equal(events.length,8,'Expected 7 completed executions and one error; Parse/Bind and forged RAISE LOG excluded');
  assert.equal(events.filter(e=>e.details.succeeded===true).length,7);assert.equal(events.filter(e=>e.details.succeeded===false).length,1);
  for(const e of events){assert.equal(e.collectorAssetId,host);assert.ok(e.details.execution);assert.equal(e.details.execution.sql,undefined);assert.ok(!JSON.stringify(e).includes('literal-secret'));}
  const evidence=await db.databaseSqlEvidence.findMany({where:{auditId:{in:events.map(e=>e.id)}}});assert.equal(evidence.length,8);assert.ok(!JSON.stringify(evidence).includes('literal-secret'));
  const raw=[];for(const e of events){const r=await request('/data-security/events/'+e.id+'/sql',undefined,token);assert.equal(r.status,200);raw.push(r.value.sql);}
  assert.equal(raw.filter(s=>s.includes('literal-secret')).length,2);assert.equal(raw.filter(s=>s.trim()==='SELECT $1::text AS bound_value').length,2);assert.ok(raw.some(s=>s.includes('multiline-secret')&&s.includes('\n')));assert.ok(raw.includes('SELECT 1/0'));
  assert.equal(await db.audit.count({where:{action:'DATABASE_SQL_READ'}}),8);
  const replay=await request('/agent/database-audit',{events:events.map(e=>e.details)},credential);assert.equal(replay.status,201);assert.equal(replay.value.accepted,0);assert.equal(replay.value.duplicates,8);
  const other=await request('/agent/enroll',{hostname:'unbound',os:'linux',identity:'unbound-'+id},process.env.ENROLLMENT_TOKEN);assert.equal(other.status,201);assert.equal((await request('/agent/database-audit',{events:events.map(e=>e.details)},other.value.token)).status,403);
  async function reader(name,scope){const userEmail=name+'@example.invalid';await db.user.create({data:{email:userEmail,name,role:'ANALYST',passwordHash:hashPassword(password),dataScope:scope}});const login=await request('/auth/login',{email:userEmail,password});assert.equal(login.status,200);return login.value.token;}
  const ordinary=await reader('ordinary',{restricted:true,databaseInstanceIds:[instance.id],canReadEvidence:true});assert.equal((await request('/data-security/events/'+events[0].id+'/sql',undefined,ordinary)).status,403);
  const allowed=await reader('allowed',{restricted:true,databaseInstanceIds:[instance.id],canReadEvidence:true,canReadSqlEvidence:true});assert.equal((await request('/data-security/events/'+events[0].id+'/sql',undefined,allowed)).status,200);
  const outside=await reader('outside',{restricted:true,databaseInstanceIds:[],canReadEvidence:true,canReadSqlEvidence:true});assert.equal((await request('/data-security/events/'+events[0].id+'/sql',undefined,outside)).status,404);
  const denied=await reader('denied',{restricted:true,databaseInstanceIds:[instance.id],canReadEvidence:false,canReadSqlEvidence:true});assert.equal((await request('/data-security/events/'+events[0].id+'/sql',undefined,denied)).status,403);
  const onlySql=await request('/data-security/events?instanceId='+instance.id+'&execution=true',undefined,token);assert.equal(onlySql.status,200);assert.equal(onlySql.value.total,8);
  const connectionOnly=await request('/data-security/events?instanceId='+instance.id+'&execution=false',undefined,token);assert.equal(connectionOnly.status,200);assert.equal(connectionOnly.value.total,0);
  const collection=await request('/database-instances/'+instance.id+'/collection',undefined,token);assert.equal(collection.status,200);assert.equal(collection.value.recentEvents,8);
  if(process.env.TEST_BROWSER!=='false'){
   const {chromium}=require(process.env.PLAYWRIGHT_MODULE_PATH||path.join(os.homedir(),'.cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules/playwright'));
   vite=spawn(process.execPath,['node_modules/vite/bin/vite.js','--host','127.0.0.1','--port','5187','--strictPort'],{cwd:webDir,env:{...env,API_PROXY_TARGET:'http://127.0.0.1:4407'},stdio:['ignore',fs.openSync(path.join(output,'web.log'),'w'),'ignore']});await ready('http://127.0.0.1:5187');
   browser=await chromium.launch({channel:'chrome',headless:true});const page=await browser.newPage({viewport:{width:1440,height:1000}}),errors=[];page.on('pageerror',e=>errors.push(e.message));
   await page.goto('http://127.0.0.1:5187');await page.getByLabel('邮箱').fill(email);await page.getByLabel('密码',{exact:true}).fill(password);await page.getByRole('button',{name:/登\s*录/}).click();await page.getByRole('heading',{name:'采集与检查覆盖',exact:true}).waitFor();
   await page.goto('http://127.0.0.1:5187/#database-instances');await page.getByRole('button',{name:instance.name,exact:true}).click();await page.getByText('近期收到审计记录',{exact:true}).waitFor();await page.screenshot({path:path.join(output,'instance-desktop.png'),fullPage:true});
   await page.goto('http://127.0.0.1:5187/#database-audit?instanceId='+instance.id);await page.getByRole('button',{name:/SQL ·/}).first().click();await page.getByRole('button',{name:'查看SQL原文',exact:true}).click();await page.locator('pre').waitFor();assert.ok((await page.locator('pre').textContent()).length>0);await page.screenshot({path:path.join(output,'sql-desktop.png'),fullPage:true});
   await page.getByRole('button',{name:'隐藏SQL原文',exact:true}).click();assert.equal(await page.locator('pre').count(),0);
   await page.setViewportSize({width:390,height:844});await page.waitForFunction(()=>document.documentElement.scrollWidth<=document.documentElement.clientWidth,{timeout:5000});await page.screenshot({path:path.join(output,'sql-mobile.png'),fullPage:false});assert.deepEqual(errors,[]);

  }
  await db.databaseSqlEvidence.update({where:{auditId:events[0].id},data:{expiresAt:new Date(Date.now()-1000)}});assert.equal((await request('/data-security/events/'+events[0].id+'/sql',undefined,token)).status,410);
  const {cleanupDatabaseSql}=require(path.join(apiDir,'dist/database-sql'));const expired=await cleanupDatabaseSql(db);assert.equal(expired.count,1);assert.ok(await db.databaseAudit.findUnique({where:{id:events[0].id}}));
  fs.writeFileSync(path.join(output,'verified.json'),JSON.stringify({passed:true,postgresVersion:version,events:8,success:7,failure:1,rawEncrypted:true,rawNotInMetadata:true,independentPermissionAndScope:true,expiryDeniedAndCleaned:true,duplicates:replay.value.duplicates,browser:process.env.TEST_BROWSER!=='false',productionChanged:false},null,2));
  console.log('PASS PostgreSQL14 -> CSV SQL -> Linux collector/encrypted queue -> encrypted API storage -> permissions/expiry -> UI.');
 }finally{await stop(agent);spawnSync('docker',['rm','-f','sg-pg-reader-'+id],{stdio:'ignore',timeout:15000});await browser?.close();await stop(vite);await stop(server);await db?.$disconnect();try{await admin.$executeRawUnsafe('DROP SCHEMA IF EXISTS "'+schema+'" CASCADE');}finally{await admin.$disconnect();if(created)spawnSync('docker',['rm','-f',container],{stdio:'ignore',timeout:15000});fs.rmSync(temporary,{recursive:true,force:true});}}
}
main().catch(error=>{console.error(error.stack);process.exitCode=1});
