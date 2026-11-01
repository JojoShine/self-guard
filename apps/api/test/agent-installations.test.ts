import 'reflect-metadata';
import {test} from 'node:test';import assert from 'node:assert/strict';
import {generateKeyPairSync,sign,createHash,randomBytes} from 'node:crypto';
import {mkdtemp,rm} from 'node:fs/promises';import {tmpdir} from 'node:os';import {join} from 'node:path';import {spawnSync} from 'node:child_process';
import {AgentController} from '../src/components';import {Platform} from '../src/platform';import {Db} from '../src/db';import {InstallationService,storeArtifact,readArtifact,installationProfileInput} from '../src/installations';

test('installation profiles reject invalid custom CA before issuing a ticket',()=>{
 const profile={releaseId:'12345678-1234-4234-9234-123456789abc',server:'https://guard.example'};
 assert.equal(installationProfileInput.safeParse(profile).success,true);
 assert.equal(installationProfileInput.safeParse({...profile,caCertificate:''}).success,true);
 assert.equal(installationProfileInput.safeParse({...profile,caCertificate:'invalid certificate'}).success,false);
});

test('installation artifacts reject corrupted bytes, are immutable and refuse symlink escapes',async()=>{
 const dir=await mkdtemp(join(tmpdir(),'selfguard-artifacts-'));
 try{const bytes=Buffer.from('actual executable fixture'),digest=createHash('sha256').update(bytes).digest('hex');
  await assert.rejects(()=>storeArtifact(dir,'a'.repeat(64),bytes.length,bytes));
  await storeArtifact(dir,digest,bytes.length,bytes);assert.deepEqual(await readArtifact(dir,digest,bytes.length),bytes);
  await assert.rejects(()=>storeArtifact(dir,digest,bytes.length,Buffer.from('different bytes')));
  await assert.rejects(()=>readArtifact(dir,'../../etc/passwd',100));
  const fs=await import('node:fs/promises');await fs.unlink(join(dir,digest));await fs.symlink('/etc/passwd',join(dir,digest));await assert.rejects(()=>readArtifact(dir,digest,bytes.length));
 }finally{await rm(dir,{recursive:true,force:true});}
});
test('signed releases and one-host installation tickets preserve identity, enforce current authority and require real heartbeat acceptance',{skip:!process.env.DATABASE_URL},async()=>{
 const admin=new Db(),schema='installation_test_'+randomBytes(8).toString('hex'),dir=await mkdtemp(join(tmpdir(),'selfguard-releases-'));let db:Db|undefined;
 const previous={root:process.env.AGENT_UPGRADE_PUBLIC_KEY,dir:process.env.AGENT_ARTIFACT_DIR};
 try{await admin.$executeRawUnsafe('CREATE SCHEMA "'+schema+'"');const url=new URL(process.env.DATABASE_URL!);url.searchParams.set('schema',schema);
  const setup=spawnSync(process.execPath,['node_modules/prisma/build/index.js','db','push','--skip-generate'],{env:{...process.env,DATABASE_URL:url.toString()},encoding:'utf8'});assert.equal(setup.status,0,setup.stderr);
  db=new Db({datasourceUrl:url.toString()});const svc=new InstallationService(db);
  const user=await db.user.create({data:{email:'operator@install.local',name:'Operator',role:'ADMIN',passwordHash:'unused'}});
  const keys=generateKeyPairSync('ed25519'),bytes=Buffer.from('release fixture'),manifest={version:'1.0.0',sequence:1,sha256:createHash('sha256').update(bytes).digest('hex'),size:bytes.length,os:'linux',architecture:'arm64',expiresAt:new Date(Date.now()+86400000).toISOString()};
  process.env.AGENT_UPGRADE_PUBLIC_KEY=keys.publicKey.export({format:'der',type:'spki'}).subarray(-32).toString('base64');process.env.AGENT_ARTIFACT_DIR=dir;
  const raw=Buffer.from(JSON.stringify(manifest));const payload={manifestBytes:raw.toString('base64'),signature:sign(null,raw,keys.privateKey).toString('base64'),sourceDigest:'a'.repeat(64),license:'Internal',sbom:{bomFormat:'CycloneDX',specVersion:'1.6',components:[]}};
  const release=await svc.createRelease(user,payload);
  await assert.rejects(()=>svc.publishRelease(user,release.id));
  await svc.uploadRelease(user,release.id,bytes);await svc.publishRelease(user,release.id);
  await assert.rejects(()=>svc.uploadRelease(user,release.id,bytes));
  const packageBytes=Buffer.from('native package fixture'),packageManifest={kind:'selfguard-agent-package-v1',version:manifest.version,architecture:manifest.architecture,os:'linux',format:'deb',executableSha256:manifest.sha256,sha256:createHash('sha256').update(packageBytes).digest('hex'),size:packageBytes.length,expiresAt:manifest.expiresAt};const packageRaw=Buffer.from(JSON.stringify(packageManifest));
  const pkg=await svc.createPackage(user,release.id,{manifestBytes:packageRaw.toString('base64'),signature:sign(null,packageRaw,keys.privateKey).toString('base64')});
  await assert.rejects(()=>svc.publishPackage(user,pkg.id));await assert.rejects(()=>svc.uploadPackage(user,pkg.id,Buffer.from('corrupt package')));
  await svc.uploadPackage(user,pkg.id,packageBytes);await svc.publishPackage(user,pkg.id);assert.deepEqual((await svc.downloadPackage(pkg.id)).bytes,packageBytes);await assert.rejects(()=>svc.uploadPackage(user,pkg.id,packageBytes));
  const task=await svc.createInstallation(user,{releaseId:release.id,server:'https://guard.example',business:'payments',tags:['prod'],executorEnabled:false});
  assert.ok(task.ticket);assert.ok(!JSON.stringify(await svc.listInstallations(user,{})).includes(task.ticket));
  const claim={identity:'persistent-host-identity',credential:randomBytes(32).toString('base64url'),hostname:'host',architecture:'arm64'};
  const first=await svc.claim(task.id,task.ticket,claim);const again=await svc.claim(task.id,claim.credential,claim);assert.equal(first.assetId,again.assetId);assert.equal(first.token,claim.credential);
  await assert.rejects(()=>svc.claim(task.id,task.ticket,{...claim,identity:'second-host'}));
  await assert.rejects(()=>svc.report(task.id,claim.credential,{status:'SUCCEEDED',version:'1.0.0'}));
  const inventory={architecture:'arm64',agentDiagnostics:{version:'1.0.0'},packages:[],packageCollection:{complete:true},distributionCollection:{complete:true},serviceCollection:{complete:true},portCollection:{complete:true}};
  await db.asset.update({where:{id:first.assetId},data:{lastSeen:new Date(Date.now()+10),inventory:{...inventory,serviceCollection:{complete:false}}}});
  await assert.rejects(()=>svc.report(task.id,claim.credential,{status:'SUCCEEDED',version:'1.0.0'}));
  await db.asset.update({where:{id:first.assetId},data:{inventory}});
  await svc.report(task.id,claim.credential,{status:'SUCCEEDED',version:'1.0.0'});
  const exact=await svc.listInstallations(user,{q:task.id});assert.equal(exact.total,1);assert.equal(exact.items[0].id,task.id);
  assert.equal((await db.agentInstallation.findUniqueOrThrow({where:{id:task.id}})).status,'SUCCEEDED');
  await svc.revokeInstallation(user,task.id);await assert.rejects(()=>svc.claim(task.id,claim.credential,claim));
  const other=await svc.createInstallation(user,{releaseId:release.id,server:'https://guard.example',executorEnabled:false});
  await db.agentInstallation.update({where:{id:other.id},data:{expiresAt:new Date(0)}});await assert.rejects(()=>svc.claim(other.id,other.ticket,claim));
  const scoped=await db.user.create({data:{email:'scoped@install.local',name:'Scoped',role:'OPERATOR',passwordHash:'unused',dataScope:{restricted:true,businesses:['payments']}}});
  await assert.rejects(()=>svc.createInstallation(scoped,{releaseId:release.id,server:'https://guard.example',business:'other'}));
  await assert.rejects(()=>svc.createRelease(scoped,payload));assert.equal((await svc.listInstallations(scoped,{})).total,0);
  await assert.rejects(()=>svc.revokeInstallation(scoped,task.id));
  const scopedTask=await svc.createInstallation(scoped,{releaseId:release.id,server:'https://guard.example',business:'payments'});assert.equal((await svc.listInstallations(scoped,{q:scopedTask.id})).total,1);const restrictedNow=await db.user.update({where:{id:scoped.id},data:{dataScope:{restricted:true,businesses:['other']}}});assert.equal((await svc.listInstallations(restrictedNow,{q:scopedTask.id})).total,0);

  const execution=await svc.createInstallation(user,{releaseId:release.id,server:'https://guard.example',executorEnabled:true,allowedRoot:'/srv/managed'});
  const executionClaim={...claim,identity:'executor-host',credential:randomBytes(32).toString('base64url')};const enrolled=await svc.claim(execution.id,execution.ticket,executionClaim);
  const executor=generateKeyPairSync('ed25519'),pub=executor.publicKey.export({format:'der',type:'spki'}).subarray(-32).toString('base64');
  const challenge=Buffer.from(`selfguard-install-v1\n${execution.id}\n${enrolled.assetId}\n${enrolled.challenge}`);
  await assert.rejects(()=>svc.bindExecutor(execution.id,executionClaim.credential,{publicKey:pub,signature:Buffer.alloc(64).toString('base64')}));
  await svc.bindExecutor(execution.id,executionClaim.credential,{publicKey:pub,signature:sign(null,challenge,executor.privateKey).toString('base64')});
  const replacement=generateKeyPairSync('ed25519');await assert.rejects(()=>svc.bindExecutor(execution.id,executionClaim.credential,{publicKey:replacement.publicKey.export({format:'der',type:'spki'}).subarray(-32).toString('base64'),signature:sign(null,challenge,replacement.privateKey).toString('base64')}));
  await db.asset.update({where:{id:first.assetId},data:{executorPublicKey:pub,inventory:{...inventory,agentDiagnostics:{version:'1.0.0',readOnlyCollector:true,executorEnabled:false}}}});
  const waitingRepair=await db.task.create({data:{title:'Waiting for explicit executor',assetId:first.assetId,template:'FILE_PERMISSION',parameters:{path:'/srv/managed/file',mode:'0600'},status:'APPROVED',requestedBy:user.email,expiresAt:new Date(Date.now()+3600000)}}),agent=new AgentController(db,new Platform(db)),componentReq={headers:{authorization:'Bearer '+claim.credential}};
  assert.deepEqual((await agent.tasks(componentReq)).items,[]);assert.equal((await db.task.findUniqueOrThrow({where:{id:waitingRepair.id}})).status,'APPROVED');
  const enabling=await svc.createInstallation(user,{releaseId:release.id,server:'https://guard.example',targetAssetId:first.assetId,executorEnabled:true,allowedRoot:'/srv/managed'});assert.equal((await svc.claim(enabling.id,enabling.ticket,claim)).assetId,first.assetId);await assert.rejects(()=>svc.report(enabling.id,claim.credential,{status:'SUCCEEDED',version:'1.0.0'}));
  await db.asset.update({where:{id:first.assetId},data:{lastSeen:new Date(Date.now()+10),inventory:{...inventory,agentDiagnostics:{version:'1.0.0',readOnlyCollector:true,executorEnabled:true}}}});await svc.report(enabling.id,claim.credential,{status:'SUCCEEDED',version:'1.0.0'});assert.equal((await agent.tasks(componentReq)).items[0].id,waitingRepair.id);await db.task.update({where:{id:waitingRepair.id},data:{status:'CANCELLED'}});
  for(let i=0;i<16;i++)await svc.createInstallation(user,{releaseId:release.id,server:'https://guard.example',executorEnabled:false});
  const firstPage=await svc.listInstallations(user,{}),secondPage=await svc.listInstallations(user,{page:2,pageSize:15});assert.equal(firstPage.items.length,15);assert.ok(secondPage.items.length>0);assert.ok(!firstPage.items.some((a:any)=>secondPage.items.some((b:any)=>a.id===b.id)));
  const third=await svc.createInstallation(user,{releaseId:release.id,server:'https://guard.example',executorEnabled:false});await db.user.update({where:{id:user.id},data:{disabled:true}});await assert.rejects(()=>svc.claim(third.id,third.ticket,{...claim,identity:'third-host'}));
  await db.user.update({where:{id:user.id},data:{disabled:false}});await svc.revokeRelease(user,release.id);await assert.rejects(()=>svc.downloadPackage(pkg.id));
 }finally{process.env.AGENT_UPGRADE_PUBLIC_KEY=previous.root||'';process.env.AGENT_ARTIFACT_DIR=previous.dir||'';await db?.$disconnect();await admin.$executeRawUnsafe('DROP SCHEMA "'+schema+'" CASCADE');await admin.$disconnect();await rm(dir,{recursive:true,force:true});}
});
