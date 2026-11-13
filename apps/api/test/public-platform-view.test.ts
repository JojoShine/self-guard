import {test} from 'node:test';
import assert from 'node:assert/strict';
import {AgentPlatformController} from '../src/agent-platform';
import {markPublicReadOnlyUser} from '../src/public-demo';
import {Db} from '../src/db';
test('public platform settings are a pure read and do not initialize identity or validate remote endpoints',async()=>{
 const db=new Db(),keys:string[]=[];Object.defineProperty(db,'setting',{value:{findUnique:async({where}:{where:{key:string}})=>{keys.push(where.key);return null;},upsert:async()=>{throw Error('must not write');}}});
 const prior=process.env.AGENT_PLATFORM_URL;process.env.AGENT_PLATFORM_URL='https://guard.example/self-guard';
 try{const result=await new AgentPlatformController(db).options({user:markPublicReadOnlyUser({role:'VIEWER'})});assert.equal(result.configured,false);assert.equal(result.canConfigure,false);assert.deepEqual(keys.sort(),['agent-platform:connection','agent-platform:identity']);}finally{if(prior===undefined)delete process.env.AGENT_PLATFORM_URL;else process.env.AGENT_PLATFORM_URL=prior;await db.$disconnect();}
});
test('public platform settings disclose safe verified entry metadata without certificates',async()=>{
 const db=new Db(),instanceId='11111111-1111-4111-8111-111111111111';Object.defineProperty(db,'setting',{value:{findUnique:async({where}:{where:{key:string}})=>({value:where.key==='agent-platform:identity'?{instanceId}:{instanceId,server:'https://guard.example/self-guard',verifiedAt:'2026-11-13T00:00:00.000Z',caCertificate:'private-or-invalid-certificate'}})}});
 const prior=process.env.AGENT_PLATFORM_URL;delete process.env.AGENT_PLATFORM_URL;
 try{const result=await new AgentPlatformController(db).options({user:markPublicReadOnlyUser({role:'VIEWER'})});assert.equal(result.configured,true);assert.equal(result.server,'https://guard.example/self-guard');assert.equal(result.canConfigure,false);assert.equal(result.caCertificate,undefined);}finally{if(prior!==undefined)process.env.AGENT_PLATFORM_URL=prior;await db.$disconnect();}
});
