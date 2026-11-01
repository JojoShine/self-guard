import 'reflect-metadata';
import {test} from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes} from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {Db} from '../src/db';
import {AuthController} from '../src/auth';
import {hashPassword,hashToken} from '../src/security';

test('PostgreSQL login reservations share a bounded window across API replicas', {skip:!process.env.DATABASE_URL},async()=>{
 const admin=new Db(),schema='auth_rate_test_'+randomBytes(8).toString('hex');
 const url=new URL(process.env.DATABASE_URL!);url.searchParams.set('schema',schema);
 let db:Db|undefined,replica:Db|undefined;
 try {
  await admin.$executeRawUnsafe('CREATE SCHEMA "'+schema+'"');
  const setup=spawnSync(process.execPath,['node_modules/prisma/build/index.js','db','push','--skip-generate'],{env:{...process.env,DATABASE_URL:url.toString()},encoding:'utf8'});assert.equal(setup.status,0,setup.stderr);
  db=new Db({datasourceUrl:url.toString()});replica=new Db({datasourceUrl:url.toString()});
  const controllers=[new AuthController(db),new AuthController(replica)];
  const ip='192.0.2.42',key='auth-rate:'+hashToken(ip),credentials={email:'missing@test.local',password:'wrong'};
  const attempt=async(c:AuthController,body=credentials,req:any={ip})=>{try {return {status:200,body:await c.login(body,req)}}catch(error:any){return {status:error.getStatus(),body:undefined}}};
  const responses=await Promise.all(Array.from({length:24},(_,i)=>attempt(controllers[i%2],credentials,{ip,headers:{'x-forwarded-for':'198.51.100.'+i}})));
  assert.equal(responses.filter(r=>r.status===401).length,10);
  assert.equal(responses.filter(r=>r.status===403).length,14);
  let counter=await db.setting.findUniqueOrThrow({where:{key}});assert.equal((counter.value as any).count,10);
  assert.ok(!JSON.stringify(counter).includes(ip),'Only the hashed client address is persisted');
  // Expired windows reset consistently on a different replica.
  await db.setting.update({where:{key},data:{value:{count:10,until:Date.now()-1}}});
  assert.equal((await attempt(controllers[1])).status,401);
  counter=await db.setting.findUniqueOrThrow({where:{key}});assert.equal((counter.value as any).count,1);
  assert.ok((counter.value as any).until>Date.now()+890000);
  // A successful authentication clears the shared counter and preserves eight-hour sessions.
  await db.user.create({data:{email:'user@test.local',name:'Fixture',passwordHash:hashPassword('correct-password-fixture')}});
  const before=Date.now();const success=await attempt(controllers[0],{email:'user@test.local',password:'correct-password-fixture'});
  assert.equal(success.status,200);assert.equal(await db.setting.findUnique({where:{key}}),null);
  const session=await db.session.findUniqueOrThrow({where:{tokenHash:hashToken(success.body!.token)}});
  assert.ok(session.expiresAt.getTime()>=before+8*3600000 && session.expiresAt.getTime()<=Date.now()+8*3600000);
  assert.equal((await attempt(controllers[1])).status,401);
  assert.equal(((await db.setting.findUniqueOrThrow({where:{key}})).value as any).count,1);
  // Capacity is global: a new address cannot grow storage beyond the bound; existing addresses still reserve.
  await db.setting.deleteMany({where:{key:{startsWith:'auth-rate:'}}});
  await db.setting.createMany({data:Array.from({length:10000},(_,i)=>({key:'auth-rate:'+hashToken('fixture-'+i),value:{count:1,until:Date.now()+900000}}))});
  await db.setting.create({data:{key:'unrelated',value:{until:1}}});
  assert.equal((await attempt(controllers[0])).status,403);
  const existingIp='fixture-0';assert.equal((await attempt(controllers[1],credentials,{ip:existingIp})).status,401);
  assert.equal(await db.setting.count({where:{key:{startsWith:'auth-rate:'}}}),10000);
  await db.setting.update({where:{key:'auth-rate:'+hashToken('fixture-1')},data:{value:{count:1,until:1}}});
  assert.equal((await attempt(controllers[0])).status,401);
  assert.equal(await db.setting.count({where:{key:{startsWith:'auth-rate:'}}}),10000);
  assert.ok(await db.setting.findUnique({where:{key:'unrelated'}}));
 }finally{
  await db?.$disconnect();await replica?.$disconnect();
  await admin.$executeRawUnsafe('DROP SCHEMA "'+schema+'" CASCADE');await admin.$disconnect();
 }
});
