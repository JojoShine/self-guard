import 'reflect-metadata';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { NestFactory } from '@nestjs/core';
import { Module } from '@nestjs/common';
import { APP_INTERCEPTOR } from '@nestjs/core';
import { Db } from '../src/db';
import { Platform } from '../src/platform';
import { AuthController, AuthGuard } from '../src/auth';
import { PlatformController } from '../src/controllers';
import { AttachmentsController } from '../src/attachments';
import { WorkflowsController } from '../src/workflows';
import { OperationsController } from '../src/operations';
import { GovernanceController } from '../src/governance';
import { ScopeResponseInterceptor } from '../src/scope';
import { hashToken } from '../src/security';
@Module({controllers:[AuthController,AttachmentsController,WorkflowsController,OperationsController,GovernanceController,PlatformController],providers:[Db,Platform,AuthGuard,{provide:APP_INTERCEPTOR,useClass:ScopeResponseInterceptor}]}) class TestApp {}

test('isolated HTTP permissions scope lists, counts, aggregation, writes, relations, imports and evidence', {skip:!process.env.SCOPE_TEST_ISOLATED}, async()=>{
 assert.match(process.env.DATABASE_URL||'',/[?&]schema=scope_test_[a-z0-9]+(?:&|$)/);
 const app=await NestFactory.create(TestApp,{logger:false});await app.listen(0,'127.0.0.1');
 const db=app.get(Db),p=app.get(Platform);const base=await app.getUrl();
 const request=async(path:string,token='scoped',method='GET',body?:any)=>{
   const r=await fetch(base+'/'+path,{method,headers:{authorization:'Bearer '+token,'content-type':'application/json'},...(body?{body:JSON.stringify(body)}:{})});return {status:r.status,body:await r.json()};
 };
 try {
  const a=await db.asset.create({data:{hostname:'visible',os:'Linux',business:'A',inventory:{password:'top-secret'}}});
  const b=await db.asset.create({data:{hostname:'hidden',os:'Linux',business:'B'}});
  for(const [email,token,dataScope,role] of [['scoped@test.local','scoped',{restricted:true,businesses:['A'],canReadEvidence:false},'ANALYST'],['admin@test.local','admin',{},'ADMIN'],['empty@test.local','empty',{restricted:true},'VIEWER']] as const){const user=await db.user.create({data:{email,name:email,passwordHash:'unused',role,dataScope}});await db.session.create({data:{userId:user.id,tokenHash:hashToken(token),expiresAt:new Date(Date.now()+3600000)}});}
  const f=await db.finding.create({data:{dedupKey:'allowed',externalId:'allowed',assetId:a.id,title:'visible finding',kind:'RISK',severity:'HIGH',source:'test',evidence:'top-secret'}});
  const hidden=await db.finding.create({data:{dedupKey:'hidden',externalId:'hidden',assetId:b.id,title:'hidden finding',kind:'RISK',severity:'HIGH',source:'test',evidence:'top-secret'}});
  const ownIncident=await db.incident.create({data:{title:'own incident',severity:'HIGH',description:'top-secret',links:{create:{findingId:f.id}},assetIds:[a.id]}});
  const mixedIncident=await db.incident.create({data:{title:'mixed incident',severity:'HIGH',links:{create:[{findingId:f.id},{findingId:hidden.id}]},assetIds:[a.id,b.id]}});
  const task=await db.task.create({data:{title:'hidden task',assetId:b.id,template:'CONFIG_VALUE',parameters:{value:'top-secret'},requestedBy:'admin@test.local',expiresAt:new Date(Date.now()+3600000)}});
  let r=await request('assets?q=hidden');assert.equal(r.body.total,0);
  r=await request('assets');assert.equal(r.body.total,1);assert.equal(r.body.items[0].inventory,'[已隐藏]');
  r=await request('findings');assert.equal(r.body.total,1);assert.equal(r.body.items[0].evidence,'[已隐藏]');
  assert.equal((await request('assets','empty')).body.total,0);
  assert.equal((await request('assets/'+b.id)).status,404);
  assert.equal((await request('findings/'+hidden.id)).status,404);
  assert.equal((await request('tasks/'+task.id+'/approve','scoped','POST',{})).status,404);
  assert.equal((await request('incidents')).body.total,1);
  assert.equal((await request('incidents/'+mixedIncident.id)).status,404);
  assert.equal((await request('discoveries')).body.total,2);
  assert.equal((await request('discoveries?q=top-secret')).body.total,0);
  assert.equal((await request('overview')).body.assets,1);
  assert.equal((await request('operations/business-groups')).body.items.length,1);
  assert.equal((await request('operations/trends')).status,200);
  assert.equal((await request('reports/summary')).body.risks,1);
  assert.equal((await request('workflows/export?resource=findings')).body.total,1);
  assert.equal((await request('workflows/assets/'+a.id+'/relations')).body.incidents.length,1);
  assert.equal((await request('workflows/assets/'+b.id+'/archive','scoped','POST',{archived:true})).status,404);
  assert.equal((await request('workflows/findings/'+f.id+'/triage','scoped','PATCH',{relatedRiskId:hidden.id})).status,404);
  assert.equal((await request('workflows/incidents/'+ownIncident.id+'/context','scoped','PATCH',{assetIds:[b.id]})).status,404);
  assert.equal((await request('incidents/'+ownIncident.id,'scoped','PATCH',{findingIds:[hidden.id]})).status,404);
  assert.equal((await request('assets/'+a.id,'scoped','PATCH',{business:'B'})).status,400);
  assert.equal((await request('findings/'+f.id+'/comments')).status,403);
  assert.equal((await request('findings/'+f.id+'/attachments')).status,403);
  assert.equal((await request('governance/imports','scoped','POST',{items:[{assetId:b.id}]})).status,403);
  assert.equal((await request('waf-access')).status,403);
  assert.equal((await request('assets','admin')).body.total,2);
  assert.equal((await request('findings/'+f.id,'admin')).body.evidence,'top-secret');
  // Change grants without refreshing a session; guards read current permissions each request.
  await db.user.update({where:{email:'scoped@test.local'},data:{dataScope:{restricted:true,businesses:['A'],canReadEvidence:true}}});
  assert.equal((await request('findings/'+f.id+'/attachments')).status,200);
  const imported=await request('governance/imports','scoped','POST',{items:[{assetId:b.id,externalId:'unauthorized',title:'forbidden',kind:'RISK',severity:'LOW',source:'test',evidence:'test'}]});
  assert.equal(imported.body.status,'FAILED');assert.equal(await db.finding.count({where:{externalId:'unauthorized'}}),0);
  assert.equal((await request('findings/'+f.id)).body.evidence,'top-secret');
 }finally{await app.close();}
});
