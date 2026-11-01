import {test} from 'node:test';import assert from 'node:assert/strict';import {Db} from '../src/db';import {Platform} from '../src/platform';import {WorkflowsController} from '../src/workflows';
test('real workflow: read/confirm/archive/window/batch/cancel',{skip:!process.env.TEST_API_URL},async()=>{
 const db=new Db(),p=new Platform(db),w=new WorkflowsController(p);const req={user:{email:'fixture-admin',role:'ADMIN'}};
 try{
 const a=await p.create('assets',{hostname:'workflow-fixture-'+Date.now(),os:'linux'},req.user.email);
 const imported=await p.import({items:[{externalId:'workflow-'+Date.now(),title:'Workflow risk',kind:'RISK',severity:'HIGH',source:'test',assetId:a.id,evidence:'fixture'}]},req.user.email);const f=imported.items[0];
 assert.equal((await w.triage(f.id,{confirmed:true},req)).status,'CONFIRMED');
 const task=await p.create('tasks',{title:'test',assetId:a.id,template:'FILE_PERMISSION',parameters:{path:'/fixture/config',mode:'0600'}},req.user.email);
 const future=new Date(Date.now()+3600000),end=new Date(Date.now()+7200000);
 assert.equal((await w.window(task.id,{notBefore:future.toISOString(),windowEnd:end.toISOString()},req))?.status,'PENDING');
 const b=await w.batch({title:'serial batch',taskIds:[task.id],stopOnFailure:true},req);assert.equal(b.status,'RUNNING');
 await w.stop(b.id,req);assert.equal((await db.task.findUniqueOrThrow({where:{id:task.id}})).status,'CANCELLED');
 assert.ok((await w.archive(a.id,{archived:true},req)).archivedAt);
 assert.equal((await w.archive(a.id,{archived:false},req)).archivedAt,null);
 assert.equal(await db.assetChange.count({where:{assetId:a.id}}),2);
 assert.ok((await w.timeline('assets',a.id)).items.length>=3);
 }finally{await db.$disconnect();}
});
