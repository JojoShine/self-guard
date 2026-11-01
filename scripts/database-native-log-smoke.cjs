const fs=require('node:fs'),{execFileSync}=require('node:child_process'),assert=require('node:assert/strict');
const version=process.env.AGENT_DATABASE_CANDIDATE||'0.4.4';assert.match(version,/^\d+\.\d+\.\d+$/);
const name='selfguard-db-audit-validation',output='.artifacts/results/expansion';
function docker(args,options={}){return execFileSync('docker',args,{encoding:'utf8',stdio:['pipe','pipe','pipe'],...options})}
async function main(){
 let started=false;
 try{
 docker(['run','-d','--name',name,'--network','none','--cpus','1','--memory','512m','--tmpfs','/var/lib/postgresql/data','-e','POSTGRES_PASSWORD=fixture-only-password','-e','POSTGRES_INITDB_ARGS=--auth-host=scram-sha-256','postgres:17-bookworm','-c','logging_collector=on','-c','log_destination=jsonlog','-c','log_directory=/var/lib/postgresql/data/log','-c','log_filename=audit.log']);started=true;
 let ready=false;for(let i=0;i<100;i++){try{docker(['exec',name,'pg_isready','-h','127.0.0.1']);ready=true;break}catch{}await new Promise(r=>setTimeout(r,200))}assert.ok(ready);
 for(let i=0;i<3;i++){let rejected=false;try{docker(['exec','-e','PGPASSWORD=invalid-test-password',name,'psql','-h','127.0.0.1','-U','audit_fixture_user','-d','postgres','-c','SELECT 1'])}catch{rejected=true}assert.ok(rejected,'Actual database must reject login')}
 await new Promise(r=>setTimeout(r,300));const raw=docker(['exec',name,'cat','/var/lib/postgresql/data/log/audit.json']);fs.writeFileSync(output+'/postgres-real-auth.jsonl',raw);
 const records=raw.trim().split('\n').map(line=>JSON.parse(line)),failures=records.filter(row=>row.state_code==='28P01');assert.ok(failures.length>=3);assert.ok(failures.every(row=>row.remote_host==='127.0.0.1'));
 const input={rule:{id:'native-pg-auth',kind:'LOG',name:'真实数据库认证失败验证',config:{type:'DATABASE_AUTH',service:'postgresql',path:'/authorized/audit.json',threshold:3,windowSeconds:300}},asset:{id:'fixture'},fixture:{source:'/authorized/audit.json',lines:raw.trim().split('\n')}};
 const result=JSON.parse(docker(['run','--rm','-i','--network','none','-v',process.cwd()+':/workspace:ro','selfguard-waf-toolchain:1.27.3-pcre2','/workspace/.artifacts/releases/'+version+'/arm64/selfguard-agent','--test-rule'],{input:JSON.stringify(input)}));assert.equal(result.matched,true);assert.equal(result.status,'COMPLETED');assert.equal(result.evidence.filter(row=>row.severity!=='INFO')[0].evidence.sourceIp,'127.0.0.1');
 fs.writeFileSync(output+'/postgres-real-auth-result.json',JSON.stringify(result,null,2));console.log('PASS actual isolated PostgreSQL password rejections -> native jsonlog -> signed '+version+' Agent detection; no production traffic');
 }finally{if(started){fs.writeFileSync(output+'/postgres-real-auth-container.log',docker(['logs',name]));docker(['rm','-f',name])}}
}
main().catch(e=>{console.error(e.message);process.exitCode=1});
