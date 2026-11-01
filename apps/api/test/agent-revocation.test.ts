import 'reflect-metadata';
import {test} from 'node:test';import assert from 'node:assert/strict';import {randomBytes} from 'node:crypto';import {spawnSync} from 'node:child_process';
import {AgentRolloutController} from '../src/rollouts';import {Db} from '../src/db';import {Platform} from '../src/platform';import {AgentController} from '../src/components';import {hashToken} from '../src/security';
test('revoked agents cannot finish an already-authenticated task claim or heartbeat',{skip:!process.env.DATABASE_URL},async()=>{
 const admin=new Db(),schema='agent_revoke_'+randomBytes(8).toString('hex');let db:Db|undefined;
 try{await admin.$executeRawUnsafe('CREATE SCHEMA "'+schema+'"');const url=new URL(process.env.DATABASE_URL!);url.searchParams.set('schema',schema);const setup=spawnSync(process.execPath,['node_modules/prisma/build/index.js','db','push','--skip-generate'],{env:{...process.env,DATABASE_URL:url.toString()},encoding:'utf8'});assert.equal(setup.status,0,setup.stderr);db=new Db({datasourceUrl:url.toString()});
  for(const action of ['tasks','heartbeat','rollout'] as const){
   const token=randomBytes(32).toString('base64url'),asset=await db.asset.create({data:{hostname:'revocation-'+action,os:'linux',tokenHash:hashToken(token)}}),req={headers:{authorization:'Bearer '+token}};
   let resume!:()=>void,authenticated!:()=>void;const paused=new Promise<void>(r=>resume=r),ready=new Promise<void>(r=>authenticated=r);
   const guarded=db.$extends({query:{asset:{async findUnique({args,query}){const row=await query(args);if((args.where as any).tokenHash===hashToken(token)){authenticated();await paused;}return row;}}}});
   const controller=new AgentController(guarded as any,new Platform(db));
   const pending=action==='rollout'?new AgentRolloutController(guarded as any).poll(req):action==='tasks'?controller.tasks(req):controller.heartbeat(req,{inventory:{version:'stale-auth'},findings:[]});
   const outcome=assert.rejects(pending,/身份无效|凭据已撤销/);await ready;
   await new AgentController(db,new Platform(db)).uninstall(req,{assetId:asset.id});
   const task=action==='tasks'?await db.task.create({data:{title:'Approved after revoke',assetId:asset.id,template:'FILE_PERMISSION',parameters:{path:'/fixture/file',mode:'0600'},status:'APPROVED',requestedBy:'fixture',expiresAt:new Date(Date.now()+3600000)}}):undefined;
   resume();await outcome;
   const current=await db.asset.findUniqueOrThrow({where:{id:asset.id}});assert.equal(current.tokenHash,null);assert.equal(current.lastSeen,null);if(task)assert.equal((await db.task.findUniqueOrThrow({where:{id:task.id}})).status,'APPROVED');
  }
 }finally{await db?.$disconnect();await admin.$executeRawUnsafe('DROP SCHEMA "'+schema+'" CASCADE');await admin.$disconnect();}
});
