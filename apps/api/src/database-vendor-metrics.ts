import {Worker} from 'node:worker_threads';
import {isAbsolute} from 'node:path';
import {checkServerIdentity,setDefaultCACertificates} from 'node:tls';
import {Client} from 'pg';
import {literalLoopback} from './monitoring-contract';
import {databaseRuntimeInput,genericDatabaseMetricInput,DatabaseRuntimeConfig,GenericDatabaseMetric} from './database-runtime-contract';

type VendorEngine='oracle'|'dm'|'kingbase'|'vastbase';
type Row=Record<string,unknown>;
type Query=(sql:string)=>Promise<Row[]>;
const deadlineMs=10000;
export const vendorRuntimeSupport={
 oracle:{driver:'oracledb',minimum:'12.1 (Thin)',limitation:'11g requires separately deployed Oracle Client/Thick mode; not enabled by this sampler'},
 dm:{driver:'deployment-supplied dmdb',minimum:'DM8',limitation:'Restricted driver is not bundled. SELFGUARD_DM_DRIVER_PATH must be an absolute deployment-owned module path. Remote TLS is unavailable: tested official driver disables certificate and hostname validation.'},
 kingbase:{driver:'pg',minimum:'identity and catalog capability checked at runtime',limitation:'Proprietary server media acceptance required'},
 vastbase:{driver:'pg',minimum:'identity and catalog capability checked at runtime',limitation:'Vastbase identity required; openGauss alone is insufficient; server authentication must be supported by pg'}
} as const;

// Deliberately select aggregates only: session SQL/commands, bind values and business tables never leave the server.
export const vendorMetricQueries={
 oracle:{
  identity:"SELECT BANNER AS \"version\" FROM V$VERSION WHERE BANNER LIKE 'Oracle%Database%' AND ROWNUM = 1",
  connections:`SELECT COUNT(*) AS "connections", SUM(CASE WHEN STATUS='ACTIVE' THEN 1 ELSE 0 END) AS "active", SUM(CASE WHEN BLOCKING_SESSION_STATUS='VALID' THEN 1 ELSE 0 END) AS "waiting" FROM V$SESSION WHERE TYPE='USER'`,
  capacity:`SELECT TO_NUMBER(VALUE) AS "maxConnections" FROM V$PARAMETER WHERE NAME='sessions'`,
  counters:`SELECT MAX(CASE WHEN NAME='user commits' THEN VALUE END) AS "commits", MAX(CASE WHEN NAME='user rollbacks' THEN VALUE END) AS "rollbacks", MAX(CASE WHEN NAME='enqueue deadlocks' THEN VALUE END) AS "deadlocks" FROM V$SYSSTAT`,
  reset:`SELECT TO_CHAR(STARTUP_TIME,'YYYY-MM-DD"T"HH24:MI:SS') AS "resetAt" FROM V$INSTANCE`
 },
 dm:{
  identity:`SELECT SVR_VERSION AS "version" FROM V$INSTANCE`,
  connections:`SELECT COUNT(*) AS "connections", SUM(CASE WHEN STATE='ACTIVE' THEN 1 ELSE 0 END) AS "active" FROM V$SESSIONS`,
  capacity:`SELECT PARA_VALUE AS "maxConnections" FROM V$DM_INI WHERE PARA_NAME='MAX_SESSIONS'`,
  reset:`SELECT CAST(START_TIME AS VARCHAR(50)) AS "resetAt" FROM V$INSTANCE`
 },
 kingbase:{
  identity:`SELECT version() AS version`,
  connections:`SELECT COUNT(*) AS connections, SUM(CASE WHEN state='active' THEN 1 ELSE 0 END) AS active, SUM(CASE WHEN state LIKE 'idle in transaction%' THEN 1 ELSE 0 END) AS "idleInTransaction", SUM(CASE WHEN state IS NULL OR state='disabled' THEN 1 ELSE 0 END) AS hidden FROM sys_stat_activity`,
  waiting:`SELECT SUM(CASE WHEN wait_event_type='Lock' THEN 1 ELSE 0 END) AS waiting FROM sys_stat_activity`,
  capacity:`SHOW max_connections`,
  counters:`SELECT xact_commit AS commits,xact_rollback AS rollbacks,deadlocks,stats_reset AS "resetAt" FROM sys_stat_database WHERE datname=current_database()`
 },
 vastbase:{
  identity:`SELECT version() AS version`,
  connections:`SELECT COUNT(*) AS connections, SUM(CASE WHEN state='active' THEN 1 ELSE 0 END) AS active, SUM(CASE WHEN state LIKE 'idle in transaction%' THEN 1 ELSE 0 END) AS "idleInTransaction", SUM(CASE WHEN state IS NULL OR state='disabled' THEN 1 ELSE 0 END) AS hidden FROM pg_stat_activity`,
  waiting:`SELECT SUM(CASE WHEN waiting THEN 1 ELSE 0 END) AS waiting FROM pg_stat_activity`,
  capacity:`SHOW max_connections`,
  counters:`SELECT xact_commit AS commits,xact_rollback AS rollbacks,deadlocks,stats_reset AS "resetAt" FROM pg_stat_database WHERE datname=current_database()`
 }
} as const;

function number(value:unknown):number|undefined{
 if(typeof value!=='number'&&(typeof value!=='string'||!/^\d+(?:\.\d+)?$/.test(value)))return;
 const n=Number(value);return Number.isFinite(n)&&n>=0&&n<=Number.MAX_SAFE_INTEGER?n:undefined;
}
function normalized(row:Row):Row{return Object.fromEntries(Object.entries(row).map(([key,value])=>[key.toLowerCase(),value]));}
function text(value:unknown):string|undefined{if(typeof value!=='string')return;const trimmed=value.trim();return trimmed.length>0&&trimmed.length<=512&&!/[\x00-\x1f\x7f]/.test(trimmed)?trimmed:undefined;}

export async function collectVendorDatabaseMetrics(engine:VendorEngine,config:DatabaseRuntimeConfig,configurationVersion:number,query:Query,previous?:GenericDatabaseMetric):Promise<GenericDatabaseMetric>{
 const started=Date.now();const queries=vendorMetricQueries[engine];
 const identity=normalized((await query(queries.identity))[0]??{});const version=text(identity.version);
 const matches=version&&({oracle:/^Oracle (?:AI )?Database\b/i,dm:/^DM (?:Database Server|DBMS)|^DM[78]\b/i,kingbase:/\bKingbase(?:ES)?\b/i,vastbase:/\bVastbase\b/i}[engine]).test(version);
 if(!matches)throw new Error('DATABASE_ENGINE_MISMATCH');
 const sample:GenericDatabaseMetric={schema:'selfguard-database-metrics-v1',engine,version:version.slice(0,128),database:config.database,capturedAt:new Date().toISOString(),configurationVersion,resetAt:'',status:'PARTIAL',issues:[],transactionAgeSeconds:config.policy.transactionAgeSeconds,queryAgeSeconds:config.policy.queryAgeSeconds,latencyMs:0};
 const fields=['connections','active','idleInTransaction','waiting','maxConnections','commits','rollbacks','deadlocks'] as const;
 for(const [group,sql] of Object.entries(queries)){
  if(group==='identity')continue;
  let row:Row;
  try{row=normalized((await query(sql))[0]??{});}catch{sample.issues.push(`${group.toUpperCase()}_UNAVAILABLE`);continue;}
  for(const key of fields){const n=number(row[key.toLowerCase()]??(key==='maxConnections'?row.max_connections:undefined));if(n!==undefined&&(key!=='maxConnections'||n>0))sample[key]=n;}
  if(number(row.hidden)!==undefined&&Number(row.hidden)>0){delete sample.active;delete sample.idleInTransaction;sample.issues.push('SESSION_VISIBILITY_INCOMPLETE');}
  const reset=row.resetat;if(reset instanceof Date)sample.resetAt=reset.toISOString();else if(text(reset))sample.resetAt=String(reset).slice(0,128);
 }
 if(sample.issues.includes('SESSION_VISIBILITY_INCOMPLETE'))delete sample.waiting;
 if(!fields.some(field=>sample[field]!==undefined))throw new Error('DATABASE_STATISTICS_UNAVAILABLE');
 if(sample.connections!==undefined&&sample.maxConnections!==undefined)sample.connectionsPercent=Math.min(100,sample.connections/sample.maxConnections*100);
 for(const field of fields)if(sample[field]===undefined)sample.issues.push(`${field.replace(/[A-Z]/g,c=>'_'+c).toUpperCase()}_UNAVAILABLE`);
 sample.issues.push('LONG_TRANSACTION_METRICS_UNAVAILABLE','LONG_QUERY_METRICS_UNAVAILABLE','BLOCKING_METRICS_UNAVAILABLE','CACHE_METRICS_UNAVAILABLE','DATABASE_SIZE_UNAVAILABLE');
 if(!sample.resetAt)sample.issues.push('COUNTER_RESET_UNKNOWN');
 const elapsed=previous?(Date.parse(sample.capturedAt)-Date.parse(previous.capturedAt))/1000:0;
 if(previous&&elapsed>=1&&elapsed<=180&&sample.resetAt&&previous.resetAt===sample.resetAt&&previous.engine===engine&&previous.version===sample.version&&previous.configurationVersion===configurationVersion&&previous.database===sample.database){
  if(sample.commits!==undefined&&previous.commits!==undefined&&sample.commits>=previous.commits)sample.commitsPerSecond=(sample.commits-previous.commits)/elapsed;
  if(sample.rollbacks!==undefined&&previous.rollbacks!==undefined&&sample.rollbacks>=previous.rollbacks)sample.rollbacksPerSecond=(sample.rollbacks-previous.rollbacks)/elapsed;
  if(sample.deadlocks!==undefined&&previous.deadlocks!==undefined&&sample.deadlocks>=previous.deadlocks)sample.deadlocksIncrease=sample.deadlocks-previous.deadlocks;
 }
 sample.latencyMs=Date.now()-started;sample.issues=[...new Set(sample.issues)];
 return genericDatabaseMetricInput.parse(sample);
}

interface NativeConnection {execute(sql:string,binds:unknown[],options:Record<string,unknown>):Promise<{rows?:Row[]}>;close():Promise<void>;callTimeout?:number;}
interface NativeDriver {OUT_FORMAT_OBJECT:number;getConnection(options:Record<string,unknown>):Promise<NativeConnection>;}

async function nativeConnection(engine:'oracle'|'dm',config:DatabaseRuntimeConfig,password:string):Promise<{query:Query;close:()=>Promise<void>}>{
 // DM's official driver does not expose a verified hostname+CA policy equivalent to Node TLS.
 if(engine==='dm'&&config.tls)throw new Error('DM_TLS_VERIFICATION_UNAVAILABLE');
 let driver:NativeDriver;
 const driverPath=engine==='oracle'?'oracledb':process.env.SELFGUARD_DM_DRIVER_PATH;
 if(!driverPath||(engine==='dm'&&!isAbsolute(driverPath)))throw new Error('DATABASE_DRIVER_UNAVAILABLE');
 try{driver=require(driverPath) as NativeDriver;}catch{throw new Error('DATABASE_DRIVER_UNAVAILABLE');}
 // Trust changes are local to this worker. walletContent is unsuitable for a CA: the driver also treats it as a client private key.
 if(engine==='oracle'&&config.tls&&config.caCertificate){
  if(typeof setDefaultCACertificates!=='function')throw new Error('ORACLE_CUSTOM_CA_UNAVAILABLE');
  setDefaultCACertificates([config.caCertificate]);
 }
 const options=engine==='oracle'?{user:config.username,password,connectString:`${config.tls?'tcps':'tcp'}://${config.address.includes(':')?'['+config.address+']':config.address}:${config.port}/${config.database}?connect_timeout=5&transport_connect_timeout=5&retry_count=0`,sslServerDNMatch:true,sslAllowWeakDNMatch:false}:{user:config.username,password,connectString:`${config.address}:${config.port}`,connectTimeout:5000,socketTimeout:5000};
 let connection:NativeConnection;
 try{connection=await driver.getConnection(options);}catch(error){
  if(engine==='oracle'&&typeof error==='object'&&error!==null&&'code' in error&&error.code==='NJS-138')throw new Error('ORACLE_THIN_VERSION_UNSUPPORTED');
  throw new Error('DATABASE_CONNECTION_FAILED');
 }
 connection.callTimeout=4000;
 return {query:async(sql)=>{const result=await connection.execute(sql,[],{outFormat:driver.OUT_FORMAT_OBJECT,maxRows:2,fetchArraySize:2,resultSet:false});return result.rows??[];},close:()=>connection.close()};
}

// Runs only inside an expendable worker. Its termination also closes any socket when a driver hangs during login/close.
export async function runVendorWorker(engine:VendorEngine,config:DatabaseRuntimeConfig,password:string,configurationVersion:number,previous?:GenericDatabaseMetric):Promise<GenericDatabaseMetric>{
 if(engine==='oracle'||engine==='dm'){
  const connection=await nativeConnection(engine,config,password);
  try{return await collectVendorDatabaseMetrics(engine,config,configurationVersion,connection.query,previous);}finally{await connection.close();}
 }
 const client=new Client({host:config.address,port:config.port,database:config.database,user:config.username,password,connectionTimeoutMillis:5000,query_timeout:4000,statement_timeout:4000,application_name:'selfguard-runtime',ssl:config.tls?{rejectUnauthorized:true,servername:config.address,checkServerIdentity,...(config.caCertificate?{ca:config.caCertificate}:{})}:false});
 client.on('error',()=>{/* The bounded query reports a sanitized failure; never log server errors. */});
 try{await client.connect();return await collectVendorDatabaseMetrics(engine,config,configurationVersion,async(sql)=>(await client.query<Row>(sql)).rows,previous);}finally{await client.end();}
}

export async function readVendorDatabaseMetrics(engine:VendorEngine,config:DatabaseRuntimeConfig,password:string,configurationVersion:number,previous?:GenericDatabaseMetric):Promise<GenericDatabaseMetric>{
 if(!config.tls&&!literalLoopback(config.address))throw new Error('DATABASE_TLS_REQUIRED');
 config=databaseRuntimeInput.parse(config);
 if(engine==='oracle'&&!/^[a-zA-Z0-9_.-]{1,128}$/.test(config.database))throw new Error('DATABASE_SERVICE_INVALID');
 return new Promise((resolve,reject)=>{
  const worker=new Worker(`const {workerData,parentPort}=require('node:worker_threads');if(workerData.module.endsWith('.ts'))require('tsx/cjs');require(workerData.module).runVendorWorker(...workerData.args).then(metric=>parentPort.postMessage({metric}),error=>{const allowed=['DATABASE_ENGINE_MISMATCH','DATABASE_DRIVER_UNAVAILABLE','DATABASE_CONNECTION_FAILED','DATABASE_STATISTICS_UNAVAILABLE','DM_TLS_VERIFICATION_UNAVAILABLE','ORACLE_CUSTOM_CA_UNAVAILABLE','ORACLE_THIN_VERSION_UNSUPPORTED'];parentPort.postMessage({error:allowed.includes(error.message)?error.message:'DATABASE_COLLECTION_FAILED'});});`,{eval:true,workerData:{module:__filename,args:[engine,config,password,configurationVersion,previous]},stdout:true,stderr:true,resourceLimits:{maxOldGenerationSizeMb:64}});
  // Drivers must not stream diagnostics or server messages to application logs.
  worker.stdout?.resume();worker.stderr?.resume();let done=false;
  const finish=(error?:string,metric?:unknown)=>{if(done)return;done=true;clearTimeout(timer);void worker.terminate().then(()=>{if(error)reject(new Error(error));else{const parsed=genericDatabaseMetricInput.safeParse(metric);if(parsed.success)resolve(parsed.data);else reject(new Error('DATABASE_RESPONSE_INVALID'));}},()=>reject(new Error('DATABASE_COLLECTION_FAILED')));};
  const timer=setTimeout(()=>finish('DATABASE_COLLECTION_TIMEOUT'),deadlineMs);
  worker.once('message',(message:{error?:string;metric?:unknown})=>finish(message.error,message.metric));
  worker.once('error',()=>finish('DATABASE_COLLECTION_FAILED'));worker.once('exit',()=>{if(!done)finish('DATABASE_COLLECTION_FAILED');});
 });
}
