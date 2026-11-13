import {test} from 'node:test';
import assert from 'node:assert/strict';
import {ExecutionContextHost} from '@nestjs/core/helpers/execution-context-host';
import {AuthGuard,allow} from '../src/auth';
import {Db} from '../src/db';
import {DEMO_EMAIL,isPublicReadOnlyUser} from '../src/public-demo';
import {assertEvidence,evidenceAllowed,redactEvidence} from '../src/scope';
import {canReadDatabaseSql} from '../src/database-sql';
import {assertDatabaseSql} from '../src/database-sql';
import {AccessObservationService} from '../src/access-observation';
import {Platform} from '../src/platform';

const id='11111111-1111-4111-8111-111111111111';
const scope={restricted:false,businesses:[],assetIds:[],databaseInstanceIds:[],canReadEvidence:false,canReadSqlEvidence:false,canReadAccessEvidence:false,canExportAccessEvidence:false};
const user={id,email:DEMO_EMAIL,name:'Public reader',role:'VIEWER',disabled:false,dataScope:scope};
const setting={enabled:true,userId:id,email:DEMO_EMAIL,password:'public-reader-only',assetIds:[],accessMode:'FULL_READ_ONLY'};
function guard(account:unknown=user,config:unknown=setting){const db=new Db();Object.defineProperty(db,'session',{value:{findUnique:async()=>({expiresAt:new Date(Date.now()+60000),user:account})}});Object.defineProperty(db,'setting',{value:{findUnique:async()=>({value:config})}});return new AuthGuard(db);}
function request(method='GET',route='/assets'){return {method,path:(process.env.BASE_PATH||'')+'/api'+route,headers:{authorization:'Bearer reader-session'},user:{...user,publicReadOnly:true}};}

test('only the validated dedicated reader receives a server-bound read marker without changing its role',async()=>{
 const req=request();await guard().canActivate(new ExecutionContextHost([req]));
 assert.equal(req.user.role,'VIEWER');assert.equal(req.user.publicReadOnly,true);assert.equal(isPublicReadOnlyUser(req.user),true);
 assert.doesNotThrow(()=>allow(req,['ADMIN']));
 assert.doesNotThrow(()=>assertEvidence(req.user));assert.equal(evidenceAllowed(req.user),true);
 assert.equal(canReadDatabaseSql(req.user),false);assert.equal(req.user.dataScope.canReadAccessEvidence,false);assert.equal(req.user.dataScope.canExportAccessEvidence,false);
 assert.throws(()=>allow({...req,method:'POST'},['ADMIN']));
 assert.throws(()=>allow({...req,path:(process.env.BASE_PATH||'')+'/api/operations/credentials'},['ADMIN']));
 assert.throws(()=>allow({user:req.user},['ADMIN']));
});
test('ordinary users and forged marker fields never acquire public-reader access',async()=>{
 const req=request();await guard({...user,email:'ordinary@example.test',publicReadOnly:true}).canActivate(new ExecutionContextHost([req]));
 assert.equal(isPublicReadOnlyUser(req.user),false);assert.equal(req.user.publicReadOnly,undefined);
 assert.throws(()=>allow(req,['ADMIN']));assert.throws(()=>assertEvidence(req.user));
 assert.throws(()=>allow(request(),['ADMIN']));
 assert.throws(()=>assertEvidence({...user,publicReadOnly:true}));
});
test('reserved public identity fails closed after account or setting permission changes and denies mutation and raw GET routes',async()=>{
 for(const account of [{...user,role:'ADMIN'},{...user,disabled:true},{...user,dataScope:{...scope,canReadEvidence:true}}])await assert.rejects(guard(account).canActivate(new ExecutionContextHost([request()])));
 for(const config of [{...setting,enabled:false},{...setting,userId:'other'}])await assert.rejects(guard(user,config).canActivate(new ExecutionContextHost([request()])));
 for(const [method,path] of [['POST','/demo-workspace'],['POST','/assets'],['PATCH','/users/'+id],['DELETE','/rules/'+id],['GET','/data-security/events/'+id+'/sql'],['GET','/access-observations/'+id+'/chunks/'+id],['GET','/operations/credentials'],['GET','/agent/policy']])await assert.rejects(guard().canActivate(new ExecutionContextHost([request(method,path)])));
});
test('reader redaction preserves chart and metadata shapes, removes secrets recursively and disables write abilities',async()=>{
 const req=request();await guard().canActivate(new ExecutionContextHost([req]));
 const input={items:[{id,hostname:'host',status:'RUNNING',canManage:true,passwordHash:'hash-secret',password:'password-secret',token:'token-secret',apiKey:'api-key-secret',credentials:{user:'private',value:'credential-secret'},privateKey:'pem-secret',sql:'SELECT private_value',requestBody:'body-secret',responseBody:'response-secret',headers:{authorization:'header-secret'},detail:{other:'audit-secret'},result:{stdout:'execution-secret'},data:{points:[{at:1000,cpu:0.5,requestBytes:20,responseBytes:40}],total:3},config:{interval:60,enabled:true,secretConfigured:true,tokenConfigured:true},inventory:{cpu:{count:4},memory:{bytes:512}},canReadSql:true}],canEdit:true};
 const redacted=redactEvidence(req.user,input);
 assert.deepEqual(redacted.items[0].data,{points:[{at:1000,cpu:0.5,requestBytes:20,responseBytes:40}],total:3});
 assert.deepEqual(redacted.items[0].config,{interval:60,enabled:true,secretConfigured:true,tokenConfigured:true});
 assert.deepEqual(redacted.items[0].inventory,{cpu:{count:4},memory:{bytes:512}});
 assert.equal(redacted.canEdit,false);assert.equal(redacted.items[0].canManage,false);assert.equal(redacted.items[0].canReadSql,false);
 for(const secret of ['hash-secret','password-secret','token-secret','api-key-secret','credential-secret','pem-secret','SELECT private_value','body-secret','response-secret','header-secret','audit-secret','execution-secret'])assert.equal(JSON.stringify(redacted).includes(secret),false,secret);
 assert.equal(input.canEdit,true);assert.equal(input.items[0].password,'password-secret');
});
test('independent SQL, raw-access and export checks still reject a validated public reader before IO',async()=>{
 const req=request();await guard().canActivate(new ExecutionContextHost([req]));
 assert.throws(()=>assertDatabaseSql(req.user));
 const db=new Db(),service=new AccessObservationService(db,new Platform(db));
 await assert.rejects(service.sql(req.user,id),{status:403});
 await assert.rejects(service.readChunk(req.user,id,id,'READ'),{status:403});
 await assert.rejects(service.readChunk(req.user,id,id,'EXPORT'),{status:403});
});
test('nested freeform audit content, header variants and encrypted credentials cannot pass through metadata',async()=>{
 const req=request();await guard().canActivate(new ExecutionContextHost([req]));
 const result=redactEvidence(req.user,{data:{details:{arbitrary:'audit-secret'},requestHeaders:{other:'header-secret'},bodyBase64:'body-secret',keyCiphertext:'encrypted-secret',nested:{statementText:'SELECT account_secret',sqlText:'SQL-secret',trustRoot:'key-secret',sourceUrl:'https://example.test/source?ticket=private-ticket',route:'/app?session=private-session'}},canPublish:true,canReadEvidence:true});
 const serialized=JSON.stringify(result);
 for(const secret of ['audit-secret','header-secret','body-secret','encrypted-secret','SELECT account_secret','SQL-secret','key-secret','private-ticket','private-session'])assert.equal(serialized.includes(secret),false,secret);
 assert.equal(result.canPublish,false);assert.equal(result.canReadEvidence,false);
 assert.equal(result.data.nested.sourceUrl,'https://example.test/source');assert.equal(result.data.nested.route,'/app');
});
test('numeric chart values and fixed result states survive while configurable values remain private',async()=>{
 const req=request();await guard().canActivate(new ExecutionContextHost([req]));
 assert.deepEqual(redactEvidence(req.user,{samples:[{capturedAt:'2026-11-13',value:0.75}],result:'SUCCESS',config:{value:'private configuration',nested:{value:42}}}),{samples:[{capturedAt:'2026-11-13',value:0.75}],result:'SUCCESS',config:{nested:{value:42}}});
});
test('database audit detail shapes retain explicit metadata while excluding freeform audit values and SQL',async()=>{
 const req=request();await guard().canActivate(new ExecutionContextHost([req]));
 const details={succeeded:true,rows:8,tls:true,sessionId:'session-1',objects:[{database:'billing',schema:'public',table:'orders',columns:['id']}],execution:{durationMs:12,sqlState:'00000',sql:'SELECT private',statementText:'private SQL'},arbitrary:'private audit note'};
 assert.deepEqual(redactEvidence(req.user,{details}),{details:{succeeded:true,rows:8,tls:true,sessionId:'session-1',objects:[{database:'billing',schema:'public',table:'orders',columns:['id']}],execution:{durationMs:12,sqlState:'00000'}}});
});
test('read-only rule definitions retain structure and condition schema without original payloads or matching literals',async()=>{
 const req=request();await guard().canActivate(new ExecutionContextHost([req]));
 const definition={method:'GET',path:'/health',rule:{operator:'ALL',conditions:[{kind:'BODY_CONTAINS',value:'private matching text',negative:false}],nativeTemplate:{raw:'private original template',engineVersion:'3.11.1',sha256:'private hash'}}};
 assert.deepEqual(redactEvidence(req.user,{definition}),{definition:{method:'GET',path:'/health',rule:{operator:'ALL',conditions:[{kind:'BODY_CONTAINS',negative:false}],nativeTemplate:{engineVersion:'3.11.1'}}}});
});
test('host inventory hides process arguments, environments and file content without disrupting resource metrics',async()=>{
 const req=request();await guard().canActivate(new ExecutionContextHost([req]));
 const sensitive={argv:['database','--db-pass','private-argument'],args:'--db-pass private-args',cmd:'database --db-pass private-cmd',cmdline:'database --db-pass private-commandline',commandLine:['database','--db-pass','private-command'],env:{DB_PASS:'private-env'},environment:'DB_PASS private-environment',environmentVariables:[{name:'DB_PASS',data:'private-variable'}],content:'private-file',contents:['private-files']};
 assert.deepEqual(redactEvidence(req.user,{inventory:{processes:[{pid:123,name:'database',...sensitive}],memory:{bytes:1024}},data:{cpu:0.5}}),{inventory:{processes:[{pid:123,name:'database'}],memory:{bytes:1024}},data:{cpu:0.5}});
});
test('network template samples hide raw service banners while retaining byte counts and sample structure',async()=>{
 const req=request();await guard().canActivate(new ExecutionContextHost([req]));
 const sample={name:'network sample',expectedMatched:true,banner:'private service reply',bannerPreview:'private service preview',bannerBytes:4096,status:'CONNECTED'};
 assert.deepEqual(redactEvidence(req.user,{samples:[sample],input:{samples:[sample]}}),{samples:[{name:'network sample',expectedMatched:true,bannerBytes:4096,status:'CONNECTED'}],input:{samples:[{name:'network sample',expectedMatched:true,bannerBytes:4096,status:'CONNECTED'}]}});
});
test('freeform string details stay a renderable string without exposing their original text',async()=>{
 const req=request();await guard().canActivate(new ExecutionContextHost([req]));
 assert.deepEqual(redactEvidence(req.user,{details:'private vulnerability details'}),{details:'[已隐藏]'});
});
test('public finding contexts keep the explicit hidden-evidence contract at every nesting level',async()=>{
 const req=request();await guard().canActivate(new ExecutionContextHost([req]));
 assert.deepEqual(redactEvidence(req.user,{resource:'findings',total:1,evidence:{findings:[{evidence:'private original'}]}}),{resource:'findings',total:1,evidence:'[已隐藏]'});
 assert.deepEqual(redactEvidence(req.user,{items:[{id,evidence:'private original'}]}),{items:[{id,evidence:'[已隐藏]'}]});
});
