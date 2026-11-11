// A real Go transport + native Nuclei acceptance against owned HTTP responses only.
const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict'),{spawnSync}=require('node:child_process'),{randomBytes}=require('node:crypto');
const root=path.resolve(__dirname,'..'),api=path.join(root,'apps/api'),fixture=path.join(root,'.artifacts/results/generic-network/fixture'),directory=path.join(root,'.artifacts','generic-http-'+randomBytes(6).toString('hex')),name='selfguard-owned-generic-'+randomBytes(6).toString('hex'),docker=process.env.GENERIC_NETWORK_DOCKER||'/usr/local/bin/docker',report=path.join(root,'.artifacts/results/generic-network/http-verified.json');
function run(command,args,options={}){const r=spawnSync(command,args,{encoding:'utf8',timeout:180000,maxBuffer:8<<20,...options});assert.equal(r.status,0,r.stderr||r.stdout||r.error?.message);return r.stdout.trim()}
function server(){
 const http=require('node:http');let mode='positive';
 const entries=[{path:'/examples/jsp/snp/anything.snp',headers:{'Content-Type':'text/html'},body:'Request Information Path info Server name Remote address',similar:'Request Information Path info Server name'},
 {path:'/.env',headers:{'Content-Type':'application/octet-stream'},body:'APP_NAME=owned\nAPP_DEBUG=false\nDB_PASSWORD=owned-not-real\n',similar:'APP_NAME=owned\nAPP_DEBUG=false\n'},
 {path:'/html/log',headers:{Server:'CirCarLife Scada','Content-Type':'text/plain'},body:'user.debug user.info EVSE',similar:'user.debug user.info'},
 {path:'/',headers:{'Content-Type':'text/html'},body:'Dashboard - Ace Admin overview & stats',similar:'Dashboard - Ace Admin'},
 {path:'/',headers:{'Content-Type':'text/html'},body:'3CX Phone System Management Console',similar:'3CX Phone System documentation'}];
 for(const [index,entry]of entries.entries())http.createServer((req,res)=>{
  if(req.url.startsWith('/__fixture/')){const next=req.url.slice(11);if(!['positive','normal','auth','similar'].includes(next)){res.writeHead(400);res.end();return}mode=next;res.end('owned-generic-http-v1');return}
  if(req.method!=='GET'||req.url!==entry.path){res.writeHead(404,{'Content-Type':'text/plain'});res.end('unavailable');return}
  for(const [key,value]of Object.entries(entry.headers))res.setHeader(key,value);
  res.writeHead(mode==='auth'?401:200);res.write(mode==='normal'?'normal service':mode==='similar'?entry.similar:entry.body);res.end();
 }).listen(8101+index,'0.0.0.0');
}
let created=false;
try{
 for(const file of ['scanner','nuclei'])fs.accessSync(path.join(fixture,file),fs.constants.X_OK);
 fs.mkdirSync(directory,{recursive:true});if(fs.existsSync(report))fs.unlinkSync(report);
 run(docker,['run','-d','--name',name,'--label','selfguard.acceptance=generic-network','--memory','256m','--cpus','1','-v',fixture+':/fixture:ro','public.ecr.aws/docker/library/node:22.22.3-bookworm','node','-e','('+server.toString()+')()']);created=true;
 const host=run(docker,['inspect','--format','{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}',name]);assert.match(host,/^172\.\d+\.\d+\.\d+$/);
 run(docker,['exec',name,'node','-e',"function ready(n){require('node:http').get('http://127.0.0.1:8101/__fixture/positive',r=>process.exit(r.statusCode===200?0:1)).on('error',()=>n?setTimeout(()=>ready(n-1),100):process.exit(1))}ready(50)"]);
 const worker=path.join(directory,'worker.cjs');fs.writeFileSync(worker,'#!'+process.execPath+'\nconst {spawnSync}=require("node:child_process");const r=spawnSync('+JSON.stringify(docker)+',["exec","-i","-e","NUCLEI_BINARY=/fixture/nuclei",'+JSON.stringify(name)+',"/fixture/scanner"],{stdio:"inherit",timeout:14000});process.exit(r.status??1);\n',{mode:0o700});
 const result=spawnSync(process.execPath,['--env-file='+path.join(root,'.env'),'--import','tsx','--test','--test-concurrency=1','test/generic-network-http.test.ts'],{cwd:api,env:{...process.env,SCAN_WORKER_BINARY:path.join(root,'.artifacts/bin/scanner-'+process.platform+'-'+process.arch),NUCLEI_BINARY:path.join(root,'.artifacts/bin/nuclei-'+process.platform+'-'+process.arch),INTELLIGENCE_ARCHIVE_READER:path.join(root,'.artifacts/bin/intelligence-unzip-'+process.platform+'-'+process.arch),GENERIC_NETWORK_CONTAINER:name,GENERIC_NETWORK_DOCKER:docker,GENERIC_NETWORK_WORKER:worker,SCAN_TEST_HOST:host,GENERIC_NETWORK_REPORT:report},stdio:'inherit',timeout:660000});assert.equal(result.status,0,'Generic network HTTP acceptance failed');assert.ok(fs.existsSync(report),'HTTP acceptance must execute and emit its actual report');assert.equal(JSON.parse(fs.readFileSync(report,'utf8')).rounds.length,5);
 console.log('PASS complete official catalog → actual native compile → controlled HTTP → Nuclei proof → risk/observation → normal/401/similar/repeated-positive rescans.');
}finally{if(created)spawnSync(docker,['rm','-f',name],{stdio:'ignore',timeout:30000});fs.rmSync(directory,{recursive:true,force:true})}
