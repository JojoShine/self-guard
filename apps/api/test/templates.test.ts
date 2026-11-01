import {Platform} from '../src/platform';import {AgentController} from '../src/components';import {hashToken} from '../src/security';
import {test} from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes} from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {Db} from '../src/db';
import {RepairTemplatesController,assertTemplateEnabled,repairTemplateCatalog} from '../src/templates';

test('repair catalog contains only fixed versioned constrained templates',()=>{
 assert.deepEqual(repairTemplateCatalog.map(t=>t.id),['FILE_PERMISSION','CONFIG_VALUE','SERVICE_STATE']);
 for(const item of repairTemplateCatalog){assert.equal(item.version,'1');for(const field of ['parameters','preconditions','steps','verification','restore'] as const)assert.ok(item[field].length>0,field);}
});
test('isolated template management persists audited toggles and rejects disabled new execution',{skip:!process.env.DATABASE_URL},async()=>{
 const admin=new Db(),schema='templates_test_'+randomBytes(8).toString('hex');const url=new URL(process.env.DATABASE_URL!);url.searchParams.set('schema',schema);let db:Db|undefined;
 try{await admin.$executeRawUnsafe('CREATE SCHEMA "'+schema+'"');const setup=spawnSync(process.execPath,['node_modules/prisma/build/index.js','db','push','--skip-generate'],{env:{...process.env,DATABASE_URL:url.toString()},encoding:'utf8'});assert.equal(setup.status,0,setup.stderr);db=new Db({datasourceUrl:url.toString()});const controller=new RepairTemplatesController(db);const actor={user:{role:'ADMIN',email:'template-admin@test.local'}};
  const initial=await controller.list();assert.equal(initial.items.length,3);assert.ok(initial.items.every(t=>t.enabled));
  await assert.rejects(()=>controller.update({user:{role:'VIEWER'}},'FILE_PERMISSION',{enabled:false}));
  await assert.rejects(()=>controller.update(actor,'FILE_PERMISSION',{enabled:false,steps:['arbitrary command']}));
  await assert.rejects(()=>controller.update(actor,'ARBITRARY_SHELL',{enabled:true}));
  await controller.update(actor,'FILE_PERMISSION',{enabled:false});assert.equal((await controller.list()).items.find(t=>t.id==='FILE_PERMISSION')?.enabled,false);
  await assert.rejects(()=>db!.$transaction(tx=>assertTemplateEnabled(tx,'FILE_PERMISSION')));
  assert.equal(await db.$transaction(tx=>assertTemplateEnabled(tx,'ROLLBACK')),null);
  assert.equal(await db.$transaction(tx=>assertTemplateEnabled(tx,'VERIFY_READ')),null);
  await controller.update(actor,'FILE_PERMISSION',{enabled:true});const template=await db.$transaction(tx=>assertTemplateEnabled(tx,'FILE_PERMISSION'));assert.equal(template?.version,'1');
  const audits=await db.audit.findMany({where:{resource:'repair-templates',resourceId:'FILE_PERMISSION'}});assert.equal(audits.length,2);assert.ok(audits.every(a=>(a.detail as any).version==='1'));
  await controller.update(actor,'FILE_PERMISSION',{enabled:false});const token='template-claim-fixture-token',asset=await db.asset.create({data:{hostname:'claim-fixture',os:'linux',tokenHash:hashToken(token)}});const base={assetId:asset.id,status:'APPROVED',requestedBy:actor.user.email,expiresAt:new Date(Date.now()+3600000)};
  await db.task.createMany({data:Array.from({length:5},(_,i)=>({...base,title:'Disabled '+i,template:'FILE_PERMISSION',parameters:{path:'/fixture/file',mode:'0600'},createdAt:new Date(Date.now()-60000+i)}))});
  const allowed=await db.task.create({data:{...base,title:'Enabled config',template:'CONFIG_VALUE',parameters:{path:'/fixture/file',key:'K',expectedValue:'old',value:'new'}}});const response=await new AgentController(db,new Platform(db)).tasks({headers:{authorization:'Bearer '+token}});assert.deepEqual(response.items.map((t:any)=>t.id),[allowed.id]);

 }finally{if(db)await db.$disconnect();await admin.$executeRawUnsafe('DROP SCHEMA "'+schema+'" CASCADE');await admin.$disconnect();}
});
