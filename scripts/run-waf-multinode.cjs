// Host orchestration: ephemeral key and two owned containers; never publishes shared sites.
const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict'),{generateKeyPairSync}=require('node:crypto'),{spawnSync,spawn}=require('node:child_process');
const root=path.resolve(__dirname,'..'),names=['selfguard-runtime-acceptance-a','selfguard-runtime-acceptance-b'];
function docker(args,options={}){const r=spawnSync('docker',args,{cwd:root,encoding:'utf8',...options});assert.equal(r.status,0,r.stderr);return r.stdout.trim()}
async function main(){
 const env=Object.fromEntries(fs.readFileSync(path.join(root,'.env'),'utf8').split(/\r?\n/).filter(s=>s.includes('=')).map(s=>{const i=s.indexOf('=');return[s.slice(0,i),s.slice(i+1)]}));assert.ok(env.WAF_TOKEN?.length>=32);
 for(const name of [...names,'selfguard-runtime-acceptance-api'])assert.notEqual(spawnSync('docker',['inspect',name],{stdio:'ignore'}).status,0,'Acceptance container already exists; do not replace it');
 const dir=fs.mkdtempSync(path.join(root,'.artifacts/waf-runtime-acceptance-'));fs.chmodSync(dir,0o700);const relative=path.relative(root,dir),shared='/workspace/'+relative,created=[];
 try{
  const {privateKey,publicKey}=generateKeyPairSync('ed25519');fs.writeFileSync(path.join(dir,'private'),privateKey.export({format:'der',type:'pkcs8'}).toString('base64'),{mode:0o600});fs.writeFileSync(path.join(dir,'public'),publicKey.export({format:'der',type:'spki'}).subarray(-32).toString('base64'),{mode:0o644});
  for(const name of names)created.push(docker(['run','--detach','--name',name,'--network','selfguard-dev_default','--cpus','1','--memory','512m','--read-only','--tmpfs','/tmp:rw,nosuid,nodev,size=64m','-v',root+':/workspace:ro','-e','WAF_TOKEN','-e','WAF_API_URL=http://selfguard-runtime-acceptance-api:4400','-e','WAF_DEVELOPMENT=true','-e','WAF_TEST_LISTEN=:8082','-e','WAF_NODE_ID='+name,'-e','WAF_CONFIG=/tmp/config.json','-e','WAF_STATE_DIR=/tmp/state','-e','WAF_RULE_PUBLIC_KEY_FILE='+shared+'/public','selfguard-waf-toolchain:1.27.3-pcre2','/workspace/.artifacts/bin/waf-diagnostic'],{env:{...process.env,WAF_TOKEN:env.WAF_TOKEN}}));
  const child=spawn('docker',['compose','-f','compose.dev.yaml','-p','selfguard-dev','run','--rm','--no-deps','-T','--name','selfguard-runtime-acceptance-api','-v',root+':/workspace','-e','WAF_ACCEPTANCE_UPSTREAM=http://selfguard-runtime-acceptance-api:4401','-e','WAF_RULE_RUNTIME_ENABLED=true','-e','WAF_RULE_SIGNING_KEY_FILE='+shared+'/private','-e','WAF_TEST_URL=http://'+names[0]+':8082','api','node','test/run-isolated-http.cjs','/workspace/scripts/waf-multinode-smoke.cjs'],{cwd:root,stdio:'inherit'});
  process.exitCode=await new Promise((resolve,reject)=>{child.once('error',reject);child.once('exit',code=>resolve(code??1))});
 }finally{
  for(const id of created){const log=spawnSync('docker',['logs',id],{encoding:'utf8'});fs.writeFileSync(path.join(root,'.artifacts/results/expansion',names[created.indexOf(id)]+'.log'),log.stdout+log.stderr,{mode:0o600});docker(['rm','--force',id])}
  fs.rmSync(dir,{recursive:true,force:true});
 }
}
main().catch(error=>{console.error(error.message);process.exitCode=1});
