// Isolated API/schema and TLS identity for real Linux/systemd installation tests.
// All credentials stay in private fixture files; no production records are used.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),{spawnSync}=require('node:child_process');
const root=path.resolve(__dirname,'..'),directory=path.join(root,'.artifacts/native-agent');
function run(command,args,input){const r=spawnSync(command,args,{cwd:root,input,encoding:'utf8'});if(r.status!==0)throw Error(command+' failed: '+r.stderr);return r.stdout;}
function main(){
 fs.mkdirSync(directory,{recursive:true,mode:0o700});
 const file=path.join(directory,'config.json');let config;
 if(fs.existsSync(file))config=JSON.parse(fs.readFileSync(file,'utf8'));else{
  const source=Object.fromEntries(fs.readFileSync(path.join(root,'.env'),'utf8').split(/\r?\n/).filter(x=>x.includes('=')).map(x=>{const i=x.indexOf('=');return[x.slice(0,i),x.slice(i+1)];}));
  const keys=crypto.generateKeyPairSync('ed25519');
  config={schema:'native_agent_'+crypto.randomBytes(8).toString('hex'),email:'native-acceptance@fixture.local',password:crypto.randomBytes(32).toString('base64url'),env:{DATABASE_URL:'postgresql://selfguard:'+encodeURIComponent(source.POSTGRES_PASSWORD)+'@postgres:5432/selfguard',PORT:'4001',ENROLLMENT_TOKEN:crypto.randomBytes(32).toString('base64url'),WAF_TOKEN:crypto.randomBytes(32).toString('base64url'),DATA_ENCRYPTION_KEY:crypto.randomBytes(32).toString('hex'),TASK_SIGNING_PRIVATE_KEY:keys.privateKey.export({format:'der',type:'pkcs8'}).toString('base64'),AGENT_UPGRADE_PUBLIC_KEY:source.AGENT_UPGRADE_PUBLIC_KEY,AGENT_ARTIFACT_DIR:'/fixture/artifacts',API_TLS_CERT:'/fixture/server.crt',API_TLS_KEY:'/fixture/server.key'}};
  const u=new URL(config.env.DATABASE_URL);u.searchParams.set('schema',config.schema);config.env.DATABASE_URL=u.toString();
  fs.writeFileSync(file,JSON.stringify(config),{mode:0o600,flag:'wx'});
 }
 if(!fs.existsSync(path.join(directory,'ca.crt'))){
  run('openssl',['req','-x509','-newkey','rsa:2048','-nodes','-keyout',path.join(directory,'ca.key'),'-out',path.join(directory,'ca.crt'),'-days','30','-subj','/CN=SelfGuard native test CA','-addext','basicConstraints=critical,CA:TRUE']);
  run('openssl',['req','-new','-newkey','rsa:2048','-nodes','-keyout',path.join(directory,'server.key'),'-out',path.join(directory,'server.csr'),'-subj','/CN=host.lima.internal']);
  const extensions=path.join(directory,'server.ext');fs.writeFileSync(extensions,'subjectAltName=DNS:host.lima.internal,DNS:host.docker.internal,DNS:native-api,IP:127.0.0.1\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n');
  run('openssl',['x509','-req','-in',path.join(directory,'server.csr'),'-CA',path.join(directory,'ca.crt'),'-CAkey',path.join(directory,'ca.key'),'-CAcreateserial','-out',path.join(directory,'server.crt'),'-days','30','-extfile',extensions]);
  for(const name of ['ca.key','server.key'])fs.chmodSync(path.join(directory,name),0o600);
 }
 config.env.AGENT_UPGRADE_ORIGINS='https://host.lima.internal:14410,https://native-api:4001';
 fs.writeFileSync(file,JSON.stringify(config),{mode:0o600});
 fs.writeFileSync(path.join(directory,'api.env'),Object.entries(config.env).map(([k,v])=>k+'='+v).join('\n')+'\n',{mode:0o600});
 const bootstrap=`require('reflect-metadata');const {Db}=require('./dist/db'),{hashPassword}=require('./dist/security');const {spawnSync}=require('node:child_process');async function main(){const c=${JSON.stringify({schema:config.schema,email:config.email,password:config.password})};const admin=new Db();await admin.$executeRawUnsafe('CREATE SCHEMA IF NOT EXISTS "'+c.schema+'"');await admin.$disconnect();const u=new URL(process.env.DATABASE_URL);u.searchParams.set('schema',c.schema);const r=spawnSync(process.execPath,['node_modules/prisma/build/index.js','migrate','deploy'],{env:{...process.env,DATABASE_URL:u.toString()},encoding:'utf8'});if(r.status!==0)throw Error(r.stderr);const db=new Db({datasourceUrl:u.toString()});await db.user.upsert({where:{email:c.email},create:{email:c.email,name:'Native acceptance',role:'ADMIN',passwordHash:hashPassword(c.password)},update:{}});await db.$disconnect();console.log('Isolated schema migrated and fixture operator ready');}main().catch(e=>{console.error(e.message);process.exitCode=1});`;
 console.log(run('docker',['compose','-f','compose.dev.yaml','exec','-T','api','node','-'],bootstrap).trim());
 let exists=spawnSync('docker',['inspect','selfguard-native-api'],{stdio:'ignore'}).status===0;
 if(exists){const current=JSON.parse(run('docker',['inspect','selfguard-native-api']))[0].Config.Env;if(Object.entries(config.env).some(([k,v])=>!current.includes(k+'='+v))){run('docker',['rm','-f','selfguard-native-api']);exists=false;}}
 if(exists){run('docker',['restart','selfguard-native-api']);}else{run('docker',['run','-d','--name','selfguard-native-api','--network','selfguard-dev_default','--network-alias','native-api','--env-file',path.join(directory,'api.env'),'-p','127.0.0.1:14410:4001','-v',path.join(root,'apps/api')+':/app','-v',directory+':/fixture','--tmpfs','/tmp:rw,noexec,nosuid,size=64m,mode=1777','-w','/app','selfguard-api-dev:22-ssh','node','dist/main.js']);}
 const ready=`const https=require('node:https'),fs=require('node:fs'),deadline=Date.now()+30000;function probe(){const req=https.get({hostname:'127.0.0.1',servername:'host.lima.internal',port:4001,path:'/api/auth/me',ca:fs.readFileSync('/fixture/ca.crt')},r=>{r.resume();if(r.statusCode===401||r.statusCode===200)process.exit(0);retry()});req.on('error',retry);req.setTimeout(1000,()=>req.destroy());}function retry(){if(Date.now()>deadline)process.exit(1);setTimeout(probe,300)}probe();`;
 run('docker',['exec','selfguard-native-api','node','-e',ready]);
 console.log('Native fixture API: https://host.lima.internal:14410 (private CA, isolated schema)');
}
try{main();}catch(e){console.error(e.message);process.exitCode=1;}
