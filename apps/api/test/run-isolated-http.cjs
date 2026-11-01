// Run HTTP integration tests against a fresh schema and a separate API process.
// Never use this schema as a Prisma shadow database.
const fs=require('node:fs'),{spawn,spawnSync}=require('node:child_process'),{randomBytes}=require('node:crypto'),assert=require('node:assert/strict');
const {Db}=require('../dist/db'),{hashPassword}=require('../dist/security');
async function main(){
 const schema='http_acceptance_'+randomBytes(12).toString('hex'),url=new URL(process.env.DATABASE_URL);assert.match(schema,/^http_acceptance_[a-f0-9]{24}$/);assert.notEqual(schema,url.searchParams.get('schema')||'public');const admin=new Db();let db,server;
 try{
  await admin.$executeRawUnsafe('CREATE SCHEMA "'+schema+'"');console.log('Isolated acceptance schema: '+schema);url.searchParams.set('schema',schema);const env={...process.env,DATABASE_URL:url.href,PORT:'4400',TEST_API_URL:'http://127.0.0.1:4400/api'};
  const migrate=spawnSync(process.execPath,['node_modules/prisma/build/index.js','migrate','deploy'],{env,encoding:'utf8'});assert.equal(migrate.status,0,migrate.stderr);db=new Db({datasourceUrl:url.href});await db.user.create({data:{email:env.ADMIN_EMAIL||'admin@selfguard.local',name:'Isolated acceptance operator',role:'ADMIN',passwordHash:hashPassword(env.ADMIN_PASSWORD)}});
  server=spawn(process.execPath,['dist/main.js'],{env,stdio:['ignore','ignore','inherit']});let ready=false;for(let attempt=0;attempt<100;attempt++){try{const r=await fetch(env.TEST_API_URL+'/health');if(r.status<500){ready=true;break}}catch{}await new Promise(r=>setTimeout(r,200))}assert.ok(ready,'Isolated API did not start');
  const smoke=process.argv[2];if(smoke)assert.match(smoke,/^(?:\/workspace\/scripts\/|\/app\/test\/)[a-z0-9-]+\.cjs$/);const files=fs.readdirSync('test').filter(name=>name.endsWith('.test.ts')).sort().map(name=>'test/'+name),tests=spawn(process.execPath,smoke?[smoke]:['node_modules/tsx/dist/cli.mjs','--test','--test-concurrency=1',...files],{env,stdio:'inherit',...(smoke?{cwd:smoke.startsWith('/app/')?'/app':'/workspace'}:{})});const stopTests=()=>tests.kill('SIGTERM');process.once('SIGTERM',stopTests);let code;try{code=await new Promise((resolve,reject)=>{tests.once('exit',resolve);tests.once('error',reject)})}finally{process.removeListener('SIGTERM',stopTests)}if(code!==0)process.exitCode=code||1;
 }finally{
  if(server&&server.exitCode===null){server.kill('SIGTERM');await Promise.race([new Promise(resolve=>server.once('exit',resolve)),new Promise(resolve=>setTimeout(resolve,5000))]);if(server.exitCode===null)server.kill('SIGKILL')}
  await db?.$disconnect();await admin.$executeRawUnsafe('DROP SCHEMA "'+schema+'" CASCADE');await admin.$disconnect();console.log('Isolated HTTP acceptance schema cleaned; shared business schema was not reset');
 }
}
main().catch(error=>{console.error(error.message);process.exitCode=1});
