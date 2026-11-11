// Two real nodes in the owned reference VM; host private key stays with the isolated API.
const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict'),net=require('node:net'),{generateKeyPairSync,randomBytes,createHash}=require('node:crypto'),{spawnSync,spawn}=require('node:child_process');
const root=path.resolve(__dirname,'..');process.loadEnvFile(path.join(root,'.env'));const lima=path.join(root,'.artifacts/tools/lima/bin/limactl'),vm='waf-reference-ubuntu24',directory=fs.mkdtempSync(path.join(root,'.artifacts/waf-multinode-')),names=['selfguard-runtime-acceptance-a','selfguard-runtime-acceptance-b'],guest='/opt/selfguard-waf-load/'+path.basename(directory),binary=path.join(root,'.artifacts/waf-checker-output/waf-static');fs.chmodSync(directory,0o700);
const token=randomBytes(32).toString('base64url'),env={...process.env,LIMA_HOME:path.join(root,'.artifacts/lima'),ADMIN_PASSWORD:randomBytes(32).toString('base64url'),WAF_TOKEN:token,WAF_TEST_TOKEN:token},quote=v=>"'"+String(v).replace(/'/g,"'\\''")+"'",pids=[];let api;
function run(cmd,args,input){const r=spawnSync(cmd,args,{cwd:root,env,input,encoding:'utf8',maxBuffer:4<<20});assert.equal(r.status,0,cmd+': '+r.stderr);return r.stdout.trim()}
function shell(command){return run(lima,['shell','--workdir=/tmp',vm,'sudo','bash','-c',command])}
async function free(port){await new Promise((resolve,reject)=>{const s=net.createServer();s.once('error',reject);s.listen(port,'0.0.0.0',()=>s.close(resolve))})}
async function main(){try{
 for(const p of [4400,4401,14423,14424,18091,18092])await free(p);
 const {privateKey,publicKey}=generateKeyPairSync('ed25519');fs.writeFileSync(path.join(directory,'private'),privateKey.export({format:'der',type:'pkcs8'}).toString('base64'),{mode:0o600});fs.writeFileSync(path.join(directory,'public'),publicKey.export({format:'der',type:'spki'}).subarray(-32).toString('base64'),{mode:0o644});
 const staging='/tmp/'+path.basename(directory);run(lima,['shell','--workdir=/tmp',vm,'mkdir','-m','700',staging]);shell('test ! -e '+quote(guest)+' && install -d -m 0700 '+quote(guest));
 for(const [source,name]of [[binary,'waf'],[path.join(directory,'public'),'public']]){run(lima,['copy',source,vm+':'+staging+'/'+name]);shell('install -m '+(name==='waf'?'0755':'0644')+' '+quote(staging+'/'+name)+' '+quote(guest+'/'+name))}
 assert.equal(shell('sha256sum '+quote(guest+'/waf')).split(/\s/)[0],createHash('sha256').update(fs.readFileSync(binary)).digest('hex'));
 for(const[index,name]of names.entries()){
 const node=guest+'/'+name;shell('install -d -m 0700 '+quote(node));const settings={WAF_TOKEN:token,WAF_API_URL:'http://host.lima.internal:4400',WAF_DEVELOPMENT:'true',WAF_NODE_ID:name,WAF_LISTEN:'127.0.0.1:'+String(18091+index),WAF_TEST_LISTEN:':'+String(14423+index),WAF_CONFIG:node+'/config.json',WAF_STATE_DIR:node+'/state',WAF_RULE_PUBLIC_KEY_FILE:guest+'/public',NO_PROXY:'host.lima.internal,127.0.0.1,localhost',HTTP_PROXY:'',HTTPS_PROXY:'',GOMAXPROCS:'2',GOMEMLIMIT:'256MiB'};
 const file=path.join(directory,name+'.env');fs.writeFileSync(file,Object.entries(settings).map(([k,v])=>k+'='+quote(v)).join('\n')+'\n',{mode:0o600});run(lima,['copy',file,vm+':'+staging+'/'+name+'.env']);shell('install -m 0600 '+quote(staging+'/'+name+'.env')+' '+quote(node+'/node.env')+'; rm '+quote(staging+'/'+name+'.env')+'; set -a; . '+quote(node+'/node.env')+'; nohup '+quote(guest+'/waf')+' >'+quote(node+'/node.log')+' 2>&1 </dev/null & echo $! >'+quote(node+'/pid'));const pid=shell('cat '+quote(node+'/pid'));assert.match(pid,/^[1-9][0-9]*$/);pids.push([pid,node]);fs.rmSync(file);
 }
 api=spawn(process.execPath,['test/run-isolated-http.cjs',path.join(root,'scripts/waf-multinode-smoke.cjs')],{cwd:path.join(root,'apps/api'),env:{...env,WAF_RULE_RUNTIME_ENABLED:'true',WAF_RULE_SIGNING_KEY_FILE:path.join(directory,'private'),WAF_TEST_URL:'http://127.0.0.1:14423',WAF_DEVELOPMENT:'true',WAF_ACCEPTANCE_NATIVE:'1',WAF_ACCEPTANCE_UPSTREAM:'http://host.lima.internal:4401'},stdio:'inherit'});process.exitCode=await new Promise((resolve,reject)=>{api.once('error',reject);api.once('exit',code=>resolve(code??1))});
 }finally{
 if(api&&api.exitCode===null)api.kill('SIGTERM');
 for(const[pid,node]of pids){try{if(shell('readlink /proc/'+pid+'/exe')===guest+'/waf')shell('kill -TERM '+pid);fs.writeFileSync(path.join(directory,path.basename(node)+'.log'),shell('cat '+quote(node+'/node.log')),{mode:0o600});shell('rm -f '+quote(node+'/node.env'))}catch(error){console.error('Owned node cleanup: '+error.message)}}
 fs.rmSync(path.join(directory,'private'),{force:true});console.log('Owned two-node reports: '+path.relative(root,directory));
 }}
main().catch(error=>{console.error(error.message);process.exitCode=1});
