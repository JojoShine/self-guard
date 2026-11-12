// A disposable localhost database produces real driver frames; no production configuration is read.
const {execFileSync}=require('node:child_process');
const {createRequire}=require('node:module');
const {createHash,randomUUID}=require('node:crypto');
const {mkdirSync,writeFileSync,mkdtempSync,rmSync}=require('node:fs');
const {tmpdir}=require('node:os');
const {join,resolve}=require('node:path');
const assert=require('node:assert/strict');
const root=resolve(__dirname,'..'),apiRequire=createRequire(join(root,'apps/api/package.json'));
const {Client}=apiRequire('pg');
const {parseCapturedSql}=require(join(root,'apps/api/dist/traffic-sql.js'));
const {AccessEvidenceStore}=require(join(root,'apps/api/dist/access-evidence.js'));
const name='sg-packet-sql-'+randomUUID().slice(0,8),privateDir=mkdtempSync(join(tmpdir(),'sg-packet-sql-'));
const docker=(...args)=>execFileSync('docker',args,{encoding:'utf8',stdio:['ignore','pipe','pipe']}).trim();
const delay=ms=>new Promise(resolve=>setTimeout(resolve,ms));
async function main(){
 let client;const results=[];
 try{
  docker('run','--rm','-d','--name',name,'--memory','256m','-p','127.0.0.1::5432','-e','POSTGRES_HOST_AUTH_METHOD=trust','public.ecr.aws/docker/library/postgres:17-alpine');
  let ready=false;for(let i=0;i<60;i++){try{docker('exec',name,'pg_isready','-U','postgres');ready=true;break}catch{await delay(500)}}assert.ok(ready,'isolated database did not become ready');
  const port=Number(docker('port',name,'5432/tcp').split(':').at(-1));
  client=new Client({host:'127.0.0.1',port,user:'postgres',database:'postgres',ssl:false});
  await client.connect();
  const frames=[],stream=client.connection.stream,write=stream.write.bind(stream);
  stream.write=function(chunk,...args){frames.push(Buffer.from(chunk));return write(chunk,...args)};
  const store=new AccessEvidenceStore(privateDir,'cd'.repeat(32));
  const cases=[{query:'SELECT 42 AS synthetic_packet_sql',sql:'SELECT 42 AS synthetic_packet_sql',stage:'QUERY'},
   {query:{name:'synthetic_packet_prepare',text:'SELECT $1::integer AS synthetic_packet_sql',values:[42]},sql:'SELECT $1::integer AS synthetic_packet_sql',stage:'EXECUTE'},
   {query:{name:'synthetic_packet_prepare',text:'SELECT $1::integer AS synthetic_packet_sql',values:[43]},reason:'PREPARED_CONTEXT_MISSING'}];
  for(const item of cases){
   frames.length=0;const response=await client.query(item.query);assert.equal(response.rows.length,1);
   const request=Buffer.concat(frames),binding={sourceId:randomUUID(),eventId:randomUUID(),direction:'REQUEST',sequence:0,capturedAt:new Date().toISOString(),sha256:createHash('sha256').update(request).digest('hex')};
   const object=await store.put(binding,request),recovered=await store.read(binding,object),parsed=parseCapturedSql('POSTGRESQL',recovered);
   assert.ok(parsed.statements.length||item.reason,'No SQL from real frame: '+JSON.stringify({reasons:parsed.reasons,bytes:request.length,header:request.subarray(0,12).toString('hex')}));
   if(item.reason){assert.ok(parsed.reasons.includes(item.reason));assert.equal(parsed.statements.length,0)}else assert.deepEqual(parsed.statements,[{sql:item.sql,stage:item.stage}]);
   results.push({state:parsed.state,stages:parsed.statements.map(s=>s.stage),reasons:parsed.reasons,encryptedRoundtrip:true,requestBytes:request.length});
  }
  const output=join(root,'.artifacts/packet-sql');mkdirSync(output,{recursive:true,mode:0o700});writeFileSync(join(output,'real-pg-acceptance.json'),JSON.stringify({checkedAt:new Date().toISOString(),database:'isolated PostgreSQL17',cases:results,productionTouched:false},null,2),{mode:0o600});
  process.stdout.write(JSON.stringify({passed:results.length,productionTouched:false})+'\n');
 }finally{if(client)await client.end();try{docker('rm','-f',name)}catch(error){if(!String(error.stderr).includes('No such container'))throw error}rmSync(privateDir,{recursive:true,force:true})}
}
main().catch(error=>{process.stderr.write('Packet SQL isolated acceptance failed: '+error.message+'\n');process.exitCode=1});
