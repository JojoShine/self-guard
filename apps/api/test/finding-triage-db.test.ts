import 'reflect-metadata';
import {test} from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes} from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {Db} from '../src/db';
import {FindingTriageController} from '../src/finding-triage';

test('independent triage preserves findings, authorization, concurrency and audit',{skip:!process.env.DATABASE_URL},async()=>{
 const admin=new Db(),schema='triage_'+randomBytes(8).toString('hex');let db:Db|undefined;
 try{
  await admin.$executeRawUnsafe('CREATE SCHEMA "'+schema+'"');const url=new URL(process.env.DATABASE_URL!);url.searchParams.set('schema',schema);
  const m=spawnSync(process.execPath,['node_modules/prisma/build/index.js','migrate','deploy'],{env:{...process.env,DATABASE_URL:url.href},encoding:'utf8'});assert.equal(m.status,0,m.stderr);db=new Db({datasourceUrl:url.href});
  const controller=new FindingTriageController(db),asset=await db.asset.create({data:{hostname:'visible',os:'linux'}}),hidden=await db.asset.create({data:{hostname:'hidden',os:'linux'}});
  const user={role:'ANALYST',email:'triage@test.invalid',dataScope:{restricted:true,assetIds:[asset.id],businesses:[],databaseInstanceIds:[]}},req={user};
  async function finding(key:string,kind='RISK',assetId=asset.id){return db!.finding.create({data:{dedupKey:key,externalId:key,title:key,kind,assetId,severity:'HIGH',source:'test',evidence:'fixture'}})}
  const a=await finding('a'),b=await finding('b'),c=await finding('c'),secret=await finding('secret','RISK',hidden.id),alert=await finding('alert','ALERT');
  const body=(version:Date,duplicateOfId:string)=>({conclusion:'DUPLICATE',duplicateOfId,reason:'已核对属于同一对象与同一问题',expectedUpdatedAt:version.toISOString()});
  await assert.rejects(()=>controller.save(req,a.id,body(a.updatedAt,secret.id)));
  await assert.rejects(()=>controller.save(req,secret.id,body(secret.updatedAt,a.id)));
  await assert.rejects(()=>controller.save({user:{...user,role:'VIEWER'}},a.id,body(a.updatedAt,b.id)));
  await assert.rejects(()=>controller.save({user:{...user,dataScope:{...user.dataScope,canReadEvidence:false}}},a.id,body(a.updatedAt,b.id)));
  await assert.rejects(()=>controller.save(req,a.id,body(a.updatedAt,a.id)));
  await assert.rejects(()=>controller.save(req,a.id,body(a.updatedAt,alert.id)));
  const saved=await controller.save(req,a.id,body(a.updatedAt,b.id));assert.equal(saved.finding.status,'OPEN');assert.equal(saved.triage?.conclusion,'DUPLICATE');assert.equal(saved.triage?.duplicate?.id,b.id);
  await assert.rejects(()=>controller.save(req,a.id,body(a.updatedAt,b.id)));
  await assert.rejects(()=>controller.save(req,b.id,body(b.updatedAt,a.id)));
  await assert.rejects(()=>controller.save(req,c.id,body(c.updatedAt,a.id)));
  await db.finding.update({where:{id:b.id},data:{assetId:hidden.id}});const sanitized=await controller.read(req,a.id);assert.equal(sanitized.triage?.duplicate,null);assert.ok(!JSON.stringify(sanitized).includes(b.id));
  const insufficient=await controller.save(req,a.id,{conclusion:'INSUFFICIENT_EVIDENCE',reason:'缺少对应时段的服务端审计记录',expectedUpdatedAt:saved.finding.updatedAt.toISOString()});assert.equal(insufficient.finding.status,'OPEN');assert.equal(insufficient.triage?.duplicate,null);
  const cleared=await controller.save(req,a.id,{conclusion:'NONE',reason:'补充证据后重新开展核查',expectedUpdatedAt:insufficient.finding.updatedAt.toISOString()});assert.equal(cleared.triage,null);assert.equal(await db.audit.count({where:{resource:'findings',resourceId:a.id,action:'FINDING_TRIAGE'}}),3);
  const d=await finding('d'),e=await finding('e');const cycle=await Promise.allSettled([controller.save(req,d.id,body(d.updatedAt,e.id)),controller.save(req,e.id,body(e.updatedAt,d.id))]);assert.equal(cycle.filter(r=>r.status==='fulfilled').length,1);
 }finally{await db?.$disconnect();await admin.$executeRawUnsafe('DROP SCHEMA IF EXISTS "'+schema+'" CASCADE');await admin.$disconnect();}
});
