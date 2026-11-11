const fs=require('node:fs'),path=require('node:path'),os=require('node:os'),assert=require('node:assert/strict');
const {spawn,spawnSync}=require('node:child_process'),{randomBytes}=require('node:crypto');
const root=path.resolve(__dirname,'..'),apiDir=path.join(root,'apps/api'),webDir=path.join(root,'apps/web');
const output=path.join(root,'.artifacts/results/security-connections');fs.mkdirSync(output,{recursive:true});
const {Db}=require(path.join(apiDir,'dist/db')),{hashPassword}=require(path.join(apiDir,'dist/security'));
const pause=ms=>new Promise(resolve=>setTimeout(resolve,ms));
function docker(args,input){const r=spawnSync('docker',args,{input,encoding:'utf8',timeout:60000,maxBuffer:4<<20});assert.equal(r.status,0,'docker operation failed: '+r.stderr.slice(-700));return r.stdout;}
async function stop(child){if(child&&child.exitCode===null){child.kill('SIGTERM');await Promise.race([new Promise(r=>child.once('exit',r)),pause(3000)]);if(child.exitCode===null)child.kill('SIGKILL');}}
async function ready(url){for(let i=0;i<100;i++){try{if((await fetch(url)).ok)return;}catch{}await pause(150);}throw Error('Isolated service did not start');}
async function main(){
 const id=randomBytes(8).toString('hex'),schema='connections_accept_'+id,container='sg-pg-connections-'+id,temporary=fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(),'sg-connections-')));
 const binary=process.env.TEST_AGENT_BINARY||path.join(root,'.artifacts/bin/agent-pg-connections-linux-'+(process.arch==='arm64'?'arm64':'amd64')),image='public.ecr.aws/docker/library/postgres:14-alpine';
 const admin=new Db();let db,server,vite,agent,browser,created=false;
 try{
  const secret=randomBytes(24).toString('hex'),secretPath=path.join(temporary,'password');fs.writeFileSync(secretPath,secret,{mode:0o600});
  docker(['run','--rm','-d','--name',container,'--network','none','--cpus','1','--memory','256m','--read-only','--tmpfs','/var/lib/postgresql/data:rw,size=192m','--tmpfs','/var/run/postgresql','--tmpfs','/tmp','-v',secretPath+':/run/pg-password:ro','-e','POSTGRES_PASSWORD_FILE=/run/pg-password','-e','POSTGRES_INITDB_ARGS=--auth-host=scram-sha-256 --auth-local=peer',image,'postgres','-c','log_connections=on','-c','log_disconnections=on','-c','log_statement=none','-c','log_line_prefix=SGDB1|%n|%p|%c|%r|%e|%i|','-c','log_timezone=UTC']);created=true;
  let online=false;for(let i=0;i<120;i++){const check=spawnSync('docker',['exec',container,'sh','-c','test "$(cat /proc/1/comm)" = postgres && pg_isready -U postgres'],{encoding:'utf8',timeout:5000});if(check.status===0){online=true;break;}await pause(250);}assert.ok(online,'PostgreSQL14 did not start');
  const version=docker(['exec','-u','postgres',container,'psql','-X','-At','-U','postgres','-c','SHOW server_version']).trim();assert.match(version,/^14\./);
  const since=new Date().toISOString();await pause(100);
  for(const query of ['SELECT 1','SELECT 1','BEGIN','BEGIN; SELECT 1/0']){
   const run=spawnSync('docker',['exec','-e','PGAPPNAME=selfguard-connection-test',container,'sh','-c','PGPASSWORD=$(cat /run/pg-password); export PGPASSWORD; exec psql -X -h 127.0.0.1 -U postgres -d postgres -c "$1"','selfguard-test',query],{encoding:'utf8',timeout:15000});
   assert.equal(run.status,query.includes('1/0')?1:0);
  }
  const denied=spawnSync('docker',['exec','-e','PGPASSWORD=selfguard-deliberately-invalid',container,'psql','-X','-h','127.0.0.1','-U','postgres','-d','postgres','-c','SELECT 1'],{encoding:'utf8',timeout:15000});assert.notEqual(denied.status,0);await pause(400);
  const logs=spawnSync('docker',['logs','--since',since,container],{encoding:'utf8',timeout:10000,maxBuffer:4<<20});assert.equal(logs.status,0);
  const sourcePath=path.join(temporary,'postgres.log');fs.writeFileSync(sourcePath,logs.stdout+logs.stderr,{mode:0o600});
  await admin.$executeRawUnsafe('CREATE SCHEMA "'+schema+'"');const url=new URL(process.env.DATABASE_URL);url.searchParams.set('schema',schema);const env={...process.env,DATABASE_URL:url.href,PORT:'4407',BASE_PATH:''};
  const migrate=spawnSync(process.execPath,['node_modules/prisma/build/index.js','migrate','deploy'],{cwd:apiDir,env,encoding:'utf8'});assert.equal(migrate.status,0,migrate.stderr);db=new Db({datasourceUrl:url.href});
  const email='connections@example.invalid',password=randomBytes(20).toString('hex');await db.user.create({data:{email,name:'连接日志隔离验收',role:'ADMIN',passwordHash:hashPassword(password)}});
  server=spawn(process.execPath,['dist/main.js'],{cwd:apiDir,env,stdio:['ignore',fs.openSync(path.join(output,'api.log'),'w'),fs.openSync(path.join(output,'api-error.log'),'w')]});await ready('http://127.0.0.1:4407/healthz');
  const base='http://127.0.0.1:4407/api';
  async function request(route,body,token,method=body?'POST':'GET'){const r=await fetch(base+route,{method,headers:{'content-type':'application/json',...(token?{authorization:'Bearer '+token}:{})},...(body?{body:JSON.stringify(body)}:{})});return {status:r.status,value:await r.json()};}
  const login=await request('/auth/login',{email,password});assert.equal(login.status,200);const token=login.value.token;
  const credential=randomBytes(32).toString('hex'),identity='pg-connection-acceptance-'+id;
  const enrollment=await request('/agent/enroll',{hostname:'PG14隔离采集主机',os:'linux',identity,credential,agentVersion:'0.4.12-pg-connections.1'},process.env.ENROLLMENT_TOKEN);assert.equal(enrollment.status,201);const host=enrollment.value.assetId;
  const instanceResponse=await request('/database-instances',{name:'PostgreSQL14真实连接验收',engine:'postgresql',stableKey:'acceptance-'+id,owner:'隔离测试',hostIds:[host],auditSources:[{assetId:host,path:sourcePath,format:'postgresql-stderr'}]},token);assert.equal(instanceResponse.status,201);const instance=instanceResponse.value;
  const state=path.join(temporary,'state');fs.mkdirSync(state,{mode:0o700});
  fs.writeFileSync(path.join(state,'identity.json'),JSON.stringify({Identity:identity,assetId:host,token:credential}),{mode:0o600});
  const configPath=path.join(temporary,'collector.json');fs.writeFileSync(configPath,JSON.stringify({Server:'http://host.docker.internal:4407',AllowHTTP:true,StateDir:state,AllowedRoot:temporary,ReadOnly:true,MaxCPUs:1,MaxMemoryBytes:128<<20,MaxQueueBytes:16<<20,BytesPerSecond:1<<20}),{mode:0o600});
  agent=spawn('docker',['run','--rm','--name','sg-pg-reader-'+id,'--user',process.getuid()+':'+process.getgid(),'--cpus','1','--memory','128m','--pids-limit','32','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges','-v',temporary+':'+temporary+':ro','-v',state+':'+state+':rw','-v',binary+':/selfguard-agent:ro','-e','AGENT_CONFIG='+configPath,'--entrypoint','/selfguard-agent',image],{stdio:['ignore',fs.openSync(path.join(output,'collector.log'),'w'),fs.openSync(path.join(output,'collector-error.log'),'w')]});
  let events;for(let i=0;i<120;i++){const r=await request('/data-security/events?instanceId='+instance.id,undefined,token);assert.equal(r.status,200);events=r.value.items;if(events.length>=9)break;if(agent.exitCode!==null)throw Error('Collector exited; inspect collector-error.log');await pause(500);}
  assert.equal(events.length,9,'Expected 4 successful logins, 1 failed login, 4 disconnects');
  assert.equal(events.filter(e=>e.operation==='LOGIN'&&e.details.succeeded===true).length,4);assert.equal(events.filter(e=>e.operation==='LOGIN'&&e.details.succeeded===false).length,1);assert.equal(events.filter(e=>e.operation==='LOGOUT').length,4);
  for(const e of events){assert.equal(e.collectorAssetId,host);assert.equal(e.sourceIp,'127.0.0.1');assert.ok(e.details.sessionId);assert.equal(e.details.tls,undefined);for(const key of ['sql','message','password'])assert.equal(e.details[key],undefined);}
  const replay=await request('/agent/database-audit',{events:events.map(e=>e.details)},credential);assert.equal(replay.status,201);assert.equal(replay.value.accepted,0);assert.equal(replay.value.duplicates,9);
  const other=await request('/agent/enroll',{hostname:'unbound',os:'linux',identity:'unbound-'+id},process.env.ENROLLMENT_TOKEN);assert.equal(other.status,201);
  assert.equal((await request('/agent/database-audit',{events:events.map(e=>e.details)},other.value.token)).status,403);
  const collection=await request('/database-instances/'+instance.id+'/collection',undefined,token);assert.equal(collection.status,200);assert.equal(collection.value.sources,1);assert.equal(collection.value.hosts.reporting,1);assert.equal(collection.value.recentEvents,9);
  if(process.env.TEST_BROWSER!=='false'){
   const {chromium}=require(process.env.PLAYWRIGHT_MODULE_PATH||path.join(os.homedir(),'.cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules/playwright'));
   vite=spawn(process.execPath,['node_modules/vite/bin/vite.js','--host','127.0.0.1','--port','5187','--strictPort'],{cwd:webDir,env:{...env,API_PROXY_TARGET:'http://127.0.0.1:4407'},stdio:['ignore',fs.openSync(path.join(output,'web.log'),'w'),'ignore']});await ready('http://127.0.0.1:5187');
   browser=await chromium.launch({channel:'chrome',headless:true});const page=await browser.newPage({viewport:{width:1440,height:1000}}),errors=[];page.on('pageerror',e=>errors.push(e.message));
   await page.goto('http://127.0.0.1:5187');await page.getByLabel('邮箱').fill(email);await page.getByLabel('密码',{exact:true}).fill(password);await page.getByRole('button',{name:/登\s*录/}).click();await page.getByRole('heading',{name:'采集与检查覆盖',exact:true}).waitFor();
   await page.goto('http://127.0.0.1:5187/#database-instances');await page.getByRole('button',{name:instance.name,exact:true}).click();await page.getByText('近期收到审计记录',{exact:true}).waitFor();await page.screenshot({path:path.join(output,'instance-desktop.png'),fullPage:true});
   await page.goto('http://127.0.0.1:5187/#database-audit?instanceId='+instance.id);await page.getByRole('combobox',{name:'审计操作类型',exact:true}).click();const filtered=page.waitForResponse(r=>r.url().includes('/data-security/events?')&&r.url().includes('operation=LOGOUT'));await page.locator('.ant-select-dropdown:not(.ant-select-dropdown-hidden)').getByText('断开连接',{exact:true}).click();await filtered;await page.screenshot({path:path.join(output,'disconnect-desktop.png'),fullPage:true});
   await page.locator('.ant-select-dropdown:not(.ant-select-dropdown-hidden)').waitFor({state:'hidden'});await page.setViewportSize({width:390,height:844});await page.waitForFunction(()=>document.documentElement.scrollWidth<=document.documentElement.clientWidth,{timeout:5000});await page.screenshot({path:path.join(output,'disconnect-mobile.png'),fullPage:false});const layout=await page.evaluate(()=>({width:document.documentElement.clientWidth,scroll:document.documentElement.scrollWidth,overflow:[...document.querySelectorAll('body *')].map(e=>({tag:e.tagName,className:e.className,left:e.getBoundingClientRect().left,right:e.getBoundingClientRect().right,width:e.getBoundingClientRect().width})).filter(e=>e.right>document.documentElement.clientWidth+1).slice(0,20)}));fs.writeFileSync(path.join(output,'mobile-layout.json'),JSON.stringify(layout,null,2));assert.ok(layout.scroll<=layout.width);assert.deepEqual(errors,[]);
  }
  fs.writeFileSync(path.join(output,'verified.json'),JSON.stringify({passed:true,postgresVersion:version,events:9,successfulLogins:4,failedLogins:1,disconnects:4,duplicateRetry:replay.value,collection:collection.value,unboundAgentRejected:true,temporarySchema:schema,productionChanged:false},null,2));
  console.log('PASS PostgreSQL14 -> native log -> real collector/policy/queue -> API -> query/UI, retry and scope.');
 }finally{await stop(agent);spawnSync('docker',['rm','-f','sg-pg-reader-'+id],{stdio:'ignore',timeout:15000});await browser?.close();await stop(vite);await stop(server);await db?.$disconnect();try{await admin.$executeRawUnsafe('DROP SCHEMA IF EXISTS "'+schema+'" CASCADE');}finally{await admin.$disconnect();if(created)spawnSync('docker',['rm','-f',container],{stdio:'ignore',timeout:15000});fs.rmSync(temporary,{recursive:true,force:true});}}
}
main().catch(error=>{console.error(error.message);process.exitCode=1});
