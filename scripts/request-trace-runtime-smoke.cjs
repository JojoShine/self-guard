const fs=require('node:fs'),assert=require('node:assert/strict'),{execFileSync,spawnSync}=require('node:child_process');
const env=Object.fromEntries(fs.readFileSync('.env','utf8').split(/\r?\n/).filter(s=>s.includes('=')).map(s=>{const i=s.indexOf('=');return[s.slice(0,i),s.slice(i+1)]}));
const name='selfguard-trace-validation';
let owned=false;
try{
 execFileSync('docker',['run','-d','--name',name,'--network','selfguard-dev_default','--cpus','1','--memory','512m','--tmpfs','/state:uid=10001,gid=10001,mode=0700','-e','WAF_TOKEN','-e','WAF_API_URL=http://api:4400','-e','WAF_DEVELOPMENT=true','-e','WAF_NODE_ID=owned-trace-validation','-e','WAF_STATE_DIR=/state','-e','WAF_CONFIG=/state/config.json','selfguard-waf:request-trace'],{encoding:'utf8',env:{...process.env,WAF_TOKEN:env.WAF_TOKEN},stdio:['ignore','pipe','pipe']});owned=true;
 const result=spawnSync('docker',['compose','-f','compose.dev.yaml','-p','selfguard-dev','exec','-T','-e','TEST_WAF_URL=http://'+name+':8081','api','node','test/run-isolated-http.cjs','/app/test/data-security-http.cjs'],{stdio:'inherit'});
 assert.equal(result.status,0);console.log('PASS owned runtime node with isolated schema; business sites, certificates and hosts unchanged');
}finally{if(owned)execFileSync('docker',['rm','-f',name],{stdio:'ignore'})}
