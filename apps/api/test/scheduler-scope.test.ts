import 'reflect-metadata';
import {test} from 'node:test';import assert from 'node:assert/strict';import {randomBytes} from 'node:crypto';import {spawnSync} from 'node:child_process';
import {Db} from '../src/db';import {Platform} from '../src/platform';import {Lifecycle} from '../src/lifecycle';
test('background notification sweep uses current recipient scope',{skip:!process.env.DATABASE_URL},async()=>{
 const admin=new Db(),schema='scheduler_test_'+randomBytes(8).toString('hex');let db:Db|undefined;
 try{await admin.$executeRawUnsafe('CREATE SCHEMA "'+schema+'"');const url=new URL(process.env.DATABASE_URL!);url.searchParams.set('schema',schema);const setup=spawnSync(process.execPath,['node_modules/prisma/build/index.js','db','push','--skip-generate'],{env:{...process.env,DATABASE_URL:url.toString()},encoding:'utf8'});assert.equal(setup.status,0,setup.stderr);
 db=new Db({datasourceUrl:url.toString()});const user=await db.user.create({data:{email:'scoped@test.local',name:'Scoped',passwordHash:'unused',role:'ANALYST',dataScope:{restricted:true,businesses:['A']}}});
 for(const business of ['A','B']){const asset=await db.asset.create({data:{hostname:business,os:'linux',business}});await db.finding.create({data:{dedupKey:business,externalId:business,title:business,assetId:asset.id,kind:'RISK',severity:'CRITICAL',source:'test',evidence:'private',owner:user.email}});}
 await new Lifecycle(db,new Platform(db)).sweep();const rows=await db.notification.findMany({where:{userId:user.id}});assert.equal(rows.length,1);assert.match(rows[0].title,/A$/);
 }finally{await db?.$disconnect();await admin.$executeRawUnsafe('DROP SCHEMA "'+schema+'" CASCADE');await admin.$disconnect();}
});
