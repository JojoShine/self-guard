// Temporarily pause only this project's four owned Agent fixture VMs. The WAF
// reference owns its separate Debian13 VM and restores it independently.
const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict'),os=require('node:os'),{createHash}=require('node:crypto'),{spawn,spawnSync}=require('node:child_process');
const seconds=Number(process.env.WAF_PERSISTENT_SECONDS||1800);assert.ok(Number.isInteger(seconds)&&seconds>=1&&seconds<=1800);
const root=path.resolve(__dirname,'..'),home=path.join(root,'.artifacts/lima'),lima=path.join(root,'.artifacts/tools/lima/bin/limactl'),env={...process.env,LIMA_HOME:home};
const owned=['native-debian-12-arm64','native-rocky-9-arm64','native-ubuntu22-arm64','native-ubuntu24'];
const label=process.env.WAF_REFERENCE_LABEL||'selection';assert.match(label,/^[a-z][a-z0-9-]{0,30}$/);const engine=process.env.WAF_PERSISTENT_ENGINE||'waf-persistent-native';const expected={'waf-persistent-native':'d7f69002808c61c4ad450a807ad54b7ee2637c9b9da3cab6a64b7e040be22c86','waf-cookie-final-native':'4a432e9b0180ca4c4f0e07ba08ac4fd70f3c9a72257ab671622bc5e96ba86a20','waf-unicode-final-native':'b4ddba7638cf9840fbacb33c499740326b7ee52274b793c52c9d072918dca847','waf-pool-diagnostic-native':'645ff79462bc33c550dd579da769c31b1bc059d8a3d22f5f3d58322ebf2dc3af','waf-request-compatible-native':'cdae2466d871616ed447f5b1880e16f52e657a0be49b0f17947fe6d9e5779ff0','waf-access-timing-native':'2ff57e7ff871399b7428e3b341baeb80ac8fedc231d61e8f3a2d84f5ec2adf0f'};assert.ok(expected[engine]);
const journal=path.join(root,'.artifacts/results/expansion/waf-'+label+'-quiet-reference-state.json');
const state={createdAt:new Date().toISOString(),phase:'PREFLIGHT',host:{memoryBytes:os.totalmem(),logicalCPUs:os.cpus().length},original:[],paused:[],restored:[],restoreErrors:[]};
function save(){fs.writeFileSync(journal,JSON.stringify(state,null,2)+'\n',{mode:0o600})}
function run(args){const result=spawnSync(lima,args,{cwd:root,env,encoding:'utf8',timeout:90000,maxBuffer:4<<20});if(result.status!==0)throw Error('Owned fixture operation failed: '+args[0]+' '+result.stderr.slice(-2000));return result.stdout}
function list(){return run(['list','--json']).trim().split('\n').filter(Boolean).map(line=>JSON.parse(line))}
async function main(){
 const previous=fs.existsSync(journal)?JSON.parse(fs.readFileSync(journal)):null;
 assert.ok(!previous||previous.phase==='RESTORED','A previous quiet reference requires explicit fixture restoration before another run');
 assert.equal(createHash('sha256').update(fs.readFileSync(path.join(root,'.artifacts/bin',engine))).digest('hex'),expected[engine],'Frozen reference engine changed');
 state.seconds=seconds;state.engine=engine;state.engineSha256=expected[engine];state.upstreamPlacement=process.env.WAF_PERSISTENT_UPSTREAM_MODE||'host';const instances=list();
 if(instances.some(row=>row.name==='native-alpine-3.23-arm64'))owned.push('native-alpine-3.23-arm64');
 for(const name of owned){const instance=instances.find(row=>row.name===name);assert.ok(instance,'Owned fixture missing: '+name);assert.ok(['Running','Stopped'].includes(instance.status));assert.equal(instance.cpus,2);assert.equal(instance.memory,2*1024**3);assert.equal(fs.realpathSync(path.join(home,name)),path.join(home,name));assert.ok(fs.existsSync(path.join(home,name,'lima.yaml')));state.original.push({name,status:instance.status,cpus:instance.cpus,memory:instance.memory})}
 save();
 let awake;
 try{
  if(process.platform==='darwin'){
   awake=spawn('/usr/bin/caffeinate',['-i','-w',String(process.pid)],{stdio:'ignore'});
   await new Promise((resolve,reject)=>{awake.once('spawn',resolve);awake.once('error',reject)});
   await new Promise(resolve=>setTimeout(resolve,200));
   assert.equal(awake.exitCode,null,'Temporary test sleep-prevention lease unavailable');
   state.sleepPrevention={kind:'idle-system-sleep-process-lease',ownerPID:process.pid};save();
  }
  for(const instance of state.original.filter(row=>row.status==='Running')){run(['stop',instance.name]);state.paused.push(instance.name);save()}
  state.phase='REFERENCE_RUNNING';state.referenceStartedAt=new Date().toISOString();save();console.log('Owned Agent fixtures paused; unrelated containers and original VM resource settings untouched');
  const started=Date.now(),child=spawn(process.execPath,['scripts/run-waf-persistent-native.cjs'],{cwd:root,env:{...env,WAF_PERSISTENT_SECONDS:String(seconds)},stdio:'inherit'});
  const code=await new Promise((resolve,reject)=>{child.once('error',reject);child.once('exit',resolve)});state.referenceExitCode=code;state.referenceFinishedAt=new Date().toISOString();save();
  for(const name of ['load.json','summary.json','reference-resources.json']){const source=path.join(root,'.artifacts/results/expansion/waf-persistent-native-'+seconds+'s-'+name);if(fs.existsSync(source)&&fs.statSync(source).mtimeMs>=started)fs.copyFileSync(source,path.join(root,'.artifacts/results/expansion/waf-'+label+'-quiet-'+seconds+'s-'+name))}
  if(code!==0)process.exitCode=code||1;
 }finally{
  state.phase='RESTORING';save();
  for(const original of state.original.filter(row=>row.status==='Running')){const name=original.name;try{if(list().find(row=>row.name===name)?.status!=='Running')run(['start','--tty=false',name]);const current=list().find(row=>row.name===name);assert.equal(current.status,original.status);assert.equal(current.cpus,original.cpus);assert.equal(current.memory,original.memory);state.restored.push(name)}catch(error){state.restoreErrors.push({name,message:error.message});process.exitCode=1}save()}
  state.phase=state.restoreErrors.length?'RESTORE_REQUIRED':'RESTORED';state.finishedAt=new Date().toISOString();if(awake?.exitCode===null)awake.kill('SIGTERM');save();console.log('Quiet reference fixture restoration: '+state.phase);
 }
}
main().catch(error=>{console.error(error.message);process.exitCode=1});
