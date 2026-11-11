import test from 'node:test';
import assert from 'node:assert/strict';
import {databaseRuntimeInput} from '../src/database-runtime-contract';
import {collectVendorDatabaseMetrics, vendorMetricQueries, readVendorDatabaseMetrics} from '../src/database-vendor-metrics';

const config=databaseRuntimeInput.parse({address:'127.0.0.1',port:1521,database:'FREEPDB1',username:'monitor',tls:false});
test('identity alone cannot pass a statistics permission check',async()=>{
 await assert.rejects(collectVendorDatabaseMetrics('oracle',config,1,async(sql)=>{
  if(sql===vendorMetricQueries.oracle.identity)return [{version:'Oracle Database 23ai'}];
  throw new Error('ORA-00942');
 }),/DATABASE_STATISTICS_UNAVAILABLE/);
});
test('vendor deltas require fresh samples in the same bounded window',async()=>{
 const query=async(sql:string)=>sql===vendorMetricQueries.oracle.identity?[{version:'Oracle Database 23ai'}]:[{connections:1,commits:20,deadlocks:7,resetAt:'same-startup'}];
 const first=await collectVendorDatabaseMetrics('oracle',config,1,query);
 for(const seconds of [181,86400]){
  const old={...first,capturedAt:new Date(Date.now()-seconds*1000).toISOString(),commits:0,deadlocks:0};
  const next=await collectVendorDatabaseMetrics('oracle',config,1,query,old);
  assert.equal(next.commitsPerSecond,undefined);assert.equal(next.deadlocksIncrease,undefined);
 }
});
test('a PostgreSQL server cannot be accepted as Kingbase or Vastbase',async()=>{
 for(const engine of ['kingbase','vastbase'] as const){
  await assert.rejects(collectVendorDatabaseMetrics(engine,config,1,async()=>[{version:'PostgreSQL 16.3'}]),/DATABASE_ENGINE_MISMATCH/);
 }
});
test('Oracle missing catalog rights retain unknown counters with explicit gaps',async()=>{
 const sample=await collectVendorDatabaseMetrics('oracle',config,1,async(sql)=>{
  if(sql===vendorMetricQueries.oracle.identity)return [{version:'Oracle Database 23ai Free Release 23.0.0.0.0'}];
  if(sql===vendorMetricQueries.oracle.counters)return [{commits:1}];
  throw new Error('ORA-01031 secret server text');
 });
 assert.equal(sample.status,'PARTIAL');assert.equal(sample.connections,undefined);
 assert.ok(sample.issues.includes('CONNECTIONS_UNAVAILABLE'));
 assert.ok(!JSON.stringify(sample).includes('secret'));
});
test('DM uses its actual session and instance metadata and preserves genuine zero',async()=>{
 const sample=await collectVendorDatabaseMetrics('dm',config,3,async(sql)=>{
  if(sql===vendorMetricQueries.dm.identity)return [{version:'DM Database Server x64 V8'}];
  if(sql===vendorMetricQueries.dm.connections)return [{connections:'2',active:'0'}];
  return [];
 });
 assert.equal(sample.version,'DM Database Server x64 V8');assert.equal(sample.connections,2);assert.equal(sample.active,0);
 assert.equal(sample.deadlocks,undefined);assert.equal(sample.status,'PARTIAL');
});
test('null, invalid and unsafe numbers remain unknown instead of becoming zero',async()=>{
 const sample=await collectVendorDatabaseMetrics('oracle',config,1,async(sql)=>{
  if(sql===vendorMetricQueries.oracle.identity)return [{version:'Oracle Database 23ai'}];
  return [{connections:null,active:'NaN',maxConnections:'99999999999999999999',commits:1}];
 });
 assert.equal(sample.connections,undefined);assert.equal(sample.active,undefined);assert.equal(sample.maxConnections,undefined);
 assert.equal(sample.status,'PARTIAL');
});
test('fixed vendor queries never retrieve business SQL text or use PostgreSQL-only wait fields on Vastbase',()=>{
 for(const queries of Object.values(vendorMetricQueries))for(const sql of Object.values(queries)){
  assert.doesNotMatch(sql,/select\s+\*|sql_text|\bquery\s*[,\s]|v\$sql|stat_statements/i);
 }
 assert.match(vendorMetricQueries.kingbase.connections,/sys_stat_activity/i);
 assert.match(vendorMetricQueries.kingbase.counters,/sys_stat_database/i);
 assert.match(vendorMetricQueries.vastbase.connections,/pg_stat_activity/i);
 assert.match(vendorMetricQueries.vastbase.waiting,/\bwaiting\b/i);
 assert.doesNotMatch(vendorMetricQueries.vastbase.waiting,/wait_event_type/);
});
test('production plaintext and connection string injection are rejected before opening a socket',async()=>{
 await assert.rejects(readVendorDatabaseMetrics('oracle',{...config,address:'192.0.2.1'},'secret',1),/DATABASE_TLS_REQUIRED/);
 await assert.rejects(readVendorDatabaseMetrics('oracle',{...config,database:'x)(HOST=evil'},'secret',1),/DATABASE_SERVICE_INVALID/);
});
test('the DM production path refuses the driver TLS policy before connecting',async()=>{
 await assert.rejects(readVendorDatabaseMetrics('dm',{...config,tls:true,address:'192.0.2.1'},'secret',1),/DM_TLS_VERIFICATION_UNAVAILABLE/);
});
test('DM requires a deployment supplied driver and does not silently bundle the restricted package',async()=>{
 const old=process.env.SELFGUARD_DM_DRIVER_PATH;delete process.env.SELFGUARD_DM_DRIVER_PATH;
 try{await assert.rejects(readVendorDatabaseMetrics('dm',config,'secret',1),/DATABASE_DRIVER_UNAVAILABLE/);}
 finally{if(old!==undefined)process.env.SELFGUARD_DM_DRIVER_PATH=old;}
});
test('Oracle AI Database banners are identified without accepting an unrelated product',async()=>{
 const sample=await collectVendorDatabaseMetrics('oracle',config,1,async(sql)=>sql===vendorMetricQueries.oracle.identity?[{version:'Oracle AI Database 26ai Free Release 23.26.0.0.0'}]:[{connections:1}]);
 assert.equal(sample.engine,'oracle');assert.match(sample.version,/26ai/);
});
test('actual DM8 version metadata may end with a newline',async()=>{
 const sample=await collectVendorDatabaseMetrics('dm',config,1,async(sql)=>sql===vendorMetricQueries.dm.identity?[{version:'DM Database Server x64 V8\n'}]:[{connections:1}]);
 assert.equal(sample.version,'DM Database Server x64 V8');
});
test('hidden vendor sessions cannot produce a false zero waiting count',async()=>{
 const sample=await collectVendorDatabaseMetrics('kingbase',config,1,async(sql)=>{
  if(sql===vendorMetricQueries.kingbase.identity)return [{version:'KingbaseES V008R006C009'}];
  if(sql===vendorMetricQueries.kingbase.connections)return [{connections:4,active:1,idleInTransaction:0,hidden:3}];
  if(sql===vendorMetricQueries.kingbase.waiting)return [{waiting:0}];
  return [];
 });
 assert.equal(sample.connections,4);assert.equal(sample.active,undefined);assert.equal(sample.waiting,undefined);assert.ok(sample.issues.includes('SESSION_VISIBILITY_INCOMPLETE'));
});
