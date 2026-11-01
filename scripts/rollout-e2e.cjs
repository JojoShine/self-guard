// Runs real Linux agent processes against a dedicated API/schema and HTTPS release fixture.
// Only the fixture installation directories are executable mutation targets.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),assert=require('node:assert/strict');
const {execFileSync,spawn}=require('node:child_process');
const delay=ms=>new Promise(resolve=>setTimeout(resolve,ms));
async function until(check,label,timeout=160000){const end=Date.now()+timeout;let last;while(Date.now()<end){try{const value=await check();if(value)return value;}catch(error){last=error;}await delay(1000);}throw Error(label+' timed out'+(last?': '+last.message:''));}
function writePrivate(file,value){fs.writeFileSync(file,typeof value==='string'?value:JSON.stringify(value),{mode:0o600});fs.chmodSync(file,0o600);}
function docker(...args){return execFileSync('docker',args,{encoding:'utf8',stdio:['ignore','pipe','pipe'],maxBuffer:4<<20}).trim();}
async function hostMain(){
 const root=process.cwd(),suffix=Date.now()+'-'+crypto.randomBytes(3).toString('hex'),name='selfguard-rollout-e2e-'+suffix,schema='rollout_e2e_'+crypto.randomBytes(8).toString('hex');
 const directory=path.join(root,'.artifacts','rollout-e2e-'+suffix);fs.mkdirSync(directory,{recursive:true,mode:0o700});
 const vars=Object.fromEntries(fs.readFileSync(path.join(root,'.env'),'utf8').split('\n').filter(line=>line&&!line.startsWith('#')).map(line=>{const i=line.indexOf('=');return [line.slice(0,i),line.slice(i+1)];}));
 const {publicKey,privateKey}=crypto.generateKeyPairSync('ed25519');
 const origin='https://rollout-fixture:4443';
 const envFile=path.join(directory,'runtime.env');
 const values={DATABASE_URL:'postgresql://selfguard:'+encodeURIComponent(vars.POSTGRES_PASSWORD)+'@postgres:5432/selfguard?schema='+schema,ADMIN_EMAIL:'rollout-fixture@example.test',ADMIN_PASSWORD:crypto.randomBytes(32).toString('base64url'),ENROLLMENT_TOKEN:crypto.randomBytes(32).toString('base64url'),WAF_TOKEN:crypto.randomBytes(32).toString('base64url'),DATA_ENCRYPTION_KEY:crypto.randomBytes(32).toString('hex'),AGENT_UPGRADE_PUBLIC_KEY:publicKey.export({format:'der',type:'spki'}).subarray(-32).toString('base64'),AGENT_UPGRADE_ORIGINS:origin,SSL_CERT_FILE:'/fixture/cert.pem',FIXTURE_ROOT:'/fixture',PORT:'4000',LD_LIBRARY_PATH:'/runtime',PATH:'/runtime:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'};
 writePrivate(envFile,Object.entries(values).map(([k,v])=>k+'='+v).join('\n')+'\n');
 function psql(sql){return docker('compose','-f','compose.dev.yaml','exec','-T','postgres','psql','-U','selfguard','-d','selfguard','-v','ON_ERROR_STOP=1','-c',sql);}
 let created=false;
 try{
  psql('CREATE SCHEMA "'+schema+'"');created=true;
  console.log('Building two release binaries using the existing Go image.');
  docker('run','--rm','-v',root+':/workspace','-w','/workspace/services/agent','-e','GOCACHE=/workspace/.artifacts/go-cache','-e','CGO_ENABLED=0','golang:1.27.3-alpine','sh','-c',`go build -ldflags '-X main.agentVersion=0.1.0' -o /workspace/.artifacts/rollout-e2e-${suffix}/old-agent . && go build -ldflags '-X main.agentVersion=0.2.0' -o /workspace/.artifacts/rollout-e2e-${suffix}/new-agent .`);
  execFileSync('openssl',['req','-x509','-newkey','rsa:2048','-nodes','-keyout',path.join(directory,'key.pem'),'-out',path.join(directory,'cert.pem'),'-days','1','-subj','/CN=rollout-fixture','-addext','subjectAltName=DNS:rollout-fixture'],{stdio:'ignore'});fs.chmodSync(path.join(directory,'key.pem'),0o600);
  const architecture=docker('run','--rm','golang:1.27.3-alpine','go','env','GOARCH');
  function release(file,version,sequence){const bytes=fs.readFileSync(path.join(directory,file)),raw=Buffer.from(JSON.stringify({version,sequence,sha256:crypto.createHash('sha256').update(bytes).digest('hex'),size:bytes.length,os:'linux',architecture,expiresAt:new Date(Date.now()+3600000).toISOString()}));return {manifestBytes:raw.toString('base64'),signature:crypto.sign(null,raw,privateKey).toString('base64'),artifactUrl:origin+'/'+file};}
  writePrivate(path.join(directory,'bad-agent'),'#!/bin/sh\nexit 1\n');
  writePrivate(path.join(directory,'releases.json'),{good:release('new-agent','0.2.0',1),bad:release('bad-agent','0.3.0',2)});
  console.log('Launching an isolated API, TLS artifact host and two supervised agents on port 5184.');
  const args=['run','--rm','--name',name,'--network','selfguard-dev_default','--hostname','rollout-fixture','--add-host','rollout-fixture:127.0.0.1','--env-file',envFile,'-v',root+'/apps/api:/app','-v',root+'/.artifacts/runtime:/runtime:ro','-v',directory+':/fixture','-v',path.join(root,'scripts/rollout-e2e.cjs')+':/rollout-e2e.cjs:ro','-w','/app','-p','127.0.0.1:5184:4000','node:22-bookworm-slim','node','/rollout-e2e.cjs','--inside'];
  await new Promise((resolve,reject)=>{const child=spawn('docker',args,{stdio:['ignore','inherit','inherit']});child.on('error',reject);child.on('exit',code=>code===0?resolve():reject(Error('Isolated rollout fixture exited '+code)));});
  const summary=JSON.parse(fs.readFileSync(path.join(directory,'result.json'),'utf8'));assert.equal(summary.status,'PASSED');console.log('Evidence: '+path.join(directory,'result.json'));
 }finally{
  try{docker('rm','-f',name);}catch{}
  if(created)psql('DROP SCHEMA "'+schema+'" CASCADE');
  fs.rmSync(envFile,{force:true});
 }
}
async function fixtureMain(){
 const root=process.env.FIXTURE_ROOT,children=[],agents=[];let stopping=false,apiProcess,artifact;
 const releases=JSON.parse(fs.readFileSync(path.join(root,'releases.json'),'utf8'));
 const output=fs.openSync(path.join(root,'api.log'),'a',0o600);
 const apiBase='http://127.0.0.1:4000/api';let token='';
 async function api(route,body,method){const response=await fetch(apiBase+route,{method:method||(body?'POST':'GET'),headers:{'content-type':'application/json',authorization:'Bearer '+token},body:body===undefined?undefined:JSON.stringify(body)});const data=await response.json();if(!response.ok)throw Error(route+' returned '+response.status);return data;}
 function startAgent(index){const item=agents[index];const child=spawn(path.join(item.install,'current'),[],{env:{...process.env,AGENT_CONFIG:item.config},stdio:['ignore',item.log,item.log]});item.process=child;item.pids.push(child.pid);children.push(child);child.on('exit',(code,signal)=>{if(stopping)return;if(code===75){item.restarts++;startAgent(index);}else item.failure='unexpected exit '+code+'/'+signal;});}
 function healthy(){const bad=agents.find(a=>a.failure);if(bad)throw Error(bad.failure);if(apiProcess.exitCode!==null)throw Error('fixture API exited');}
 try{
  execFileSync(process.execPath,['node_modules/prisma/build/index.js','db','push','--skip-generate'],{stdio:['ignore',output,output]});
  execFileSync(process.execPath,['--import','tsx','prisma/seed.ts'],{stdio:['ignore',output,output]});
  artifact=require('node:https').createServer({key:fs.readFileSync(path.join(root,'key.pem')),cert:fs.readFileSync(path.join(root,'cert.pem'))},(req,res)=>{assert.equal(req.headers.authorization,undefined,'artifact request leaked credentials');const file=req.url==='/new-agent'?'new-agent':req.url==='/bad-agent'?'bad-agent':null;if(!file){res.writeHead(404);res.end();return;}const bytes=fs.readFileSync(path.join(root,file));setTimeout(()=>{res.writeHead(200,{'content-type':'application/octet-stream','content-length':bytes.length});res.end(bytes);},1500);});
  await new Promise(resolve=>artifact.listen(4443,'0.0.0.0',resolve));
  apiProcess=spawn(process.execPath,['dist/main.js'],{stdio:['ignore',output,output]});children.push(apiProcess);
  await until(async()=>{try{const login=await api('/auth/login',{email:process.env.ADMIN_EMAIL,password:process.env.ADMIN_PASSWORD});token=login.token;return !!token;}catch{return false;}},'API ready',45000);
  for(let i=0;i<2;i++){
   const install=path.join(root,'agent-'+i,'install'),state=path.join(root,'agent-'+i,'state');fs.mkdirSync(install,{recursive:true,mode:0o700});fs.mkdirSync(state,{mode:0o700});fs.copyFileSync(path.join(root,'old-agent'),path.join(install,'current'));fs.chmodSync(path.join(install,'current'),0o700);
   const config=path.join(root,'agent-'+i,'config.json');writePrivate(config,{Server:'http://127.0.0.1:4000',EnrollmentToken:process.env.ENROLLMENT_TOKEN,StateDir:state,UpgradeInstallRoot:install,UpgradePublicKey:process.env.AGENT_UPGRADE_PUBLIC_KEY,UpgradeOrigins:[process.env.AGENT_UPGRADE_ORIGINS]});
   agents.push({install,state,config,log:fs.openSync(path.join(root,'agent-'+i,'process.log'),'a',0o600),pids:[],restarts:0});startAgent(i);
  }
  await until(async()=>{healthy();for(const item of agents){const identityFile=path.join(item.state,'identity.json');if(!fs.existsSync(identityFile))return false;const identity=JSON.parse(fs.readFileSync(identityFile,'utf8'));if(!identity.assetId)return false;item.assetId=identity.assetId;const asset=await api('/assets/'+identity.assetId);if(asset.inventory?.agentDiagnostics?.version!=='0.1.0')return false;}return true;},'initial agent enrollment and heartbeat');
  console.log('Both old binaries enrolled and produced real 0.1.0 heartbeats.');
  const ids=agents.map(a=>a.assetId),rollout=await api('/rollouts',{...releases.good,targetIds:ids,batchSize:1});await api('/rollouts/'+rollout.id+'/approve',{targetIds:ids});
  let observedCanary=false,observedSecond=false;
  const healthyRow=await until(async()=>{healthy();const rows=await api('/rollouts'),row=rows.find(r=>r.id===rollout.id);const first=row.targets.find(t=>t.assetId===ids[0]),second=row.targets.find(t=>t.assetId===ids[1]);
   if(['CLAIMED','STAGED'].includes(first.status)){observedCanary=true;assert.equal(second.status,'PENDING','second target advanced before canary heartbeat');}
   if(second.status!=='PENDING'){observedSecond=true;assert.equal(first.status,'RUNNING','second claimed without verified canary');}
   if(row.status==='PAUSED')throw Error('healthy rollout unexpectedly paused');
   return row.status==='COMPLETED'?row:false;
  },'real canary and second agent upgrade',220000);
  const canary=healthyRow.targets.find(t=>t.assetId===ids[0]),next=healthyRow.targets.find(t=>t.assetId===ids[1]);assert.ok(canary.reportedAt&&next.claimedAt&&Date.parse(canary.reportedAt)<=Date.parse(next.claimedAt),'second target claimed before canary activation');assert.ok(observedCanary,'fixture did not expose the in-progress canary');assert.ok(observedSecond);for(const item of agents){assert.equal(item.restarts,1);assert.equal(item.pids.length,2);assert.notEqual(item.pids[0],item.pids[1]);const asset=await api('/assets/'+item.assetId);assert.equal(asset.inventory.agentDiagnostics.version,'0.2.0');assert.ok(fs.readFileSync(path.join(item.install,'current')).equals(fs.readFileSync(path.join(root,'new-agent'))));}
  console.log('Real process exits 75, restarts and 0.2.0 heartbeats completed canary then second target.');
  const failed=await api('/rollouts',{...releases.bad,targetIds:ids,batchSize:1});await api('/rollouts/'+failed.id+'/approve',{targetIds:ids});
  const failedRow=await until(async()=>{healthy();const row=(await api('/rollouts')).find(r=>r.id===failed.id);return row.status==='PAUSED'?row:false;},'signed failing candidate rollback and pause');
  assert.equal(failedRow.targets.find(t=>t.assetId===ids[0]).status,'FAILED');assert.equal(failedRow.targets.find(t=>t.assetId===ids[1]).status,'PENDING');assert.ok(fs.readFileSync(path.join(agents[0].install,'current')).equals(fs.readFileSync(path.join(root,'new-agent'))));assert.equal(agents[0].restarts,1);
  const summary={status:'PASSED',at:new Date().toISOString(),healthyRolloutId:rollout.id,failedRolloutId:failed.id,canaryGateObserved:observedCanary,failedSelfTestRestoredPreviousBinary:true,remainingTargetPaused:true,agents:agents.map(a=>({assetId:a.assetId,processIds:a.pids,restarts:a.restarts,verifiedVersion:'0.2.0'}))};writePrivate(path.join(root,'result.json'),summary);console.log('Signed failing candidate restored the previous binary and paused the remaining target.');
 }finally{
  stopping=true;for(const child of children)if(child.exitCode===null)child.kill('SIGTERM');if(artifact)await new Promise(resolve=>artifact.close(resolve));await delay(300);for(const child of children)if(child.exitCode===null)child.kill('SIGKILL');fs.closeSync(output);for(const item of agents)fs.closeSync(item.log);
 }
}
(process.argv.includes('--inside')?fixtureMain():hostMain()).catch(error=>{console.error(error.message);process.exitCode=1;});
