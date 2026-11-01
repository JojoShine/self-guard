import {test} from 'node:test';
import assert from 'node:assert/strict';
import {databaseBaselineInput,databaseLogInput,databaseRuleCatalog,requiresDataSecurity} from '../src/data-security';
import {requestTraceInput} from '../src/request-trace';
import {Platform} from '../src/platform';
import {AgentController} from '../src/components';
test('database templates validate through production rule validation; reject unsafe inference',()=>{
 const p=new Platform({} as any);
 for(const row of databaseRuleCatalog){
 const config=row.kind==='LOG'?{type:row.type,path:'/authorized/db.log',service:row.formats![0],threshold:row.type==='DATABASE_CLEARTEXT'?1:5,windowSeconds:60}:{type:row.type,key:row.key,path:'/authorized/db.conf'};
 p.validateRule({...row,config});
 }
 assert.equal(databaseRuleCatalog.length,7);
 assert.throws(()=>databaseLogInput.parse({type:'DATABASE_CLEARTEXT',path:'/db',service:'mysql',threshold:1,windowSeconds:60}));
 assert.throws(()=>databaseBaselineInput.parse({type:'DATABASE_SECURITY',path:'/db',key:'ARBITRARY_COMMAND'}));
 assert.equal(requiresDataSecurity({contains:'failed'}),false);
});
test('request context refuses arbitrary bodies and credentials',()=>{
 const context={requestId:'one',peerIp:'192.0.2.1',clientIp:'192.0.2.1',sourceBasis:'SOCKET_PEER',incomingTls:false,requestTargetSha256:'a'.repeat(64),pathRetention:'SANITIZED_PATH_QUERY_VALUES_NOT_RETAINED',queryKeys:['password'],queryKeysOmitted:0,forwarded:false,action:'BLOCK',outcome:'BLOCKED_BY_WAF',banState:'NO_PERSISTENT_BAN'};
 assert.equal(requestTraceInput.parse(context).outcome,'BLOCKED_BY_WAF');
 assert.throws(()=>requestTraceInput.parse({...context,body:'private'}));
 assert.throws(()=>requestTraceInput.parse({...context,configuredUpstream:'https://user:secret@db.test'}));
});
test('old Agent cannot receive new database detectors',async()=>{
 const rules=[{id:'old',config:{contains:'failed'}},{id:'new',config:{type:'DATABASE_AUTH'}}];
 const controller=new AgentController({rule:{findMany:async()=>rules}} as any,{} as any);
 (controller as any).identity=async()=>({id:'asset',tags:[],business:null});
 const old=await controller.policy({query:{}});assert.deepEqual(old.rules.map(r=>r.id),['old']);
 const malformed=await controller.policy({query:{capabilities:['data-security-v1']}});assert.deepEqual(malformed.rules.map(r=>r.id),['old']);
 const current=await controller.policy({query:{capabilities:'data-security-v1'}});assert.deepEqual(current.rules.map(r=>r.id),['old','new']);
});
