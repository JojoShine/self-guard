import {isIP} from 'node:net';import {checkServerIdentity} from 'node:tls';
import {createHash} from 'node:crypto';
import mysql,{RowDataPacket} from 'mysql2';
import {createClient} from 'redis';
import {DatabaseRuntimeConfig,GenericDatabaseMetric,genericDatabaseMetricInput,databaseRuntimeInput} from './database-runtime-contract';
const maxOutput=1024*1024;
export class DatabaseReadError extends Error{constructor(readonly safeCode:string){super(safeCode)}}
function counter(value:unknown):number|undefined{if(typeof value!=='string'&&typeof value!=='number')return;const n=Number(value);return String(value).trim()!==''&&Number.isFinite(n)&&n>=0&&n<=Number.MAX_SAFE_INTEGER?n:undefined;}
function base(engine:GenericDatabaseMetric['engine'],version:string,config:DatabaseRuntimeConfig,configurationVersion:number,latencyMs:number,reset:string){return{schema:'selfguard-database-metrics-v1' as const,engine,version:version.slice(0,128),database:config.database,capturedAt:new Date().toISOString(),configurationVersion,resetAt:createHash('sha256').update(reset).digest('hex'),status:'PARTIAL' as const,issues:[] as string[],transactionAgeSeconds:config.policy.transactionAgeSeconds,queryAgeSeconds:config.policy.queryAgeSeconds,latencyMs};}
export function databaseRates(old:GenericDatabaseMetric|undefined,current:GenericDatabaseMetric):Partial<GenericDatabaseMetric>{
 if(!old||old.engine!==current.engine||old.configurationVersion!==current.configurationVersion||old.resetAt!==current.resetAt||!current.resetAt)return{};
 const seconds=(Date.parse(current.capturedAt)-Date.parse(old.capturedAt))/1000;if(seconds<1||seconds>180||(old.uptimeSeconds!==undefined&&current.uptimeSeconds!==undefined&&current.uptimeSeconds<old.uptimeSeconds+seconds-2))return{};
 const result:Partial<GenericDatabaseMetric>={};
 for(const [source,target]of [['commands','commandsPerSecond'],['commits','commitsPerSecond'],['rollbacks','rollbacksPerSecond'],['deadlocks','deadlocksIncrease']] as const){const a=old[source],b=current[source];if(a!==undefined&&b!==undefined&&b>=a)result[target]=(b-a)/(source==='deadlocks'?1:seconds);}
 return result;
}
export function parseRedisInfo(info:string,config:DatabaseRuntimeConfig,version:number,latencyMs:number):GenericDatabaseMetric{
 if(Buffer.byteLength(info)>maxOutput)throw new DatabaseReadError('OUTPUT_LIMIT');const data=new Map(info.split(/\r?\n/).filter(line=>!line.startsWith('#')).map(line=>{const i=line.indexOf(':');return[line.slice(0,i),line.slice(i+1)]}));
 const product=data.get('redis_version')||'';if(!/^([6-9]|[1-9][0-9]+)\.\d+\.\d+(?:[-.][\w.-]+)?$/.test(product)||data.has('valkey_version')||data.has('keydb_version'))throw new DatabaseReadError('UNSUPPORTED_VERSION');
 const metric:GenericDatabaseMetric=base('redis',product,config,version,latencyMs,data.get('run_id')||'');
 if(!data.get('run_id'))metric.resetAt='';
 for(const[source,target]of [['connected_clients','connections'],['maxclients','maxConnections'],['used_memory','usedMemoryBytes'],['total_commands_processed','commands'],['keyspace_hits','keyspaceHits'],['keyspace_misses','keyspaceMisses'],['uptime_in_seconds','uptimeSeconds']]as const){const n=counter(data.get(source));if(n!==undefined&&(target!=='maxConnections'||n>0))metric[target]=n;}
 const maxMemory=counter(data.get('maxmemory'));if(maxMemory!==undefined&&maxMemory>0){metric.maxMemoryBytes=maxMemory;if(metric.usedMemoryBytes!==undefined)metric.memoryPercent=Math.min(100,100*metric.usedMemoryBytes/maxMemory);}
 if(metric.maxConnections&&metric.connections!==undefined)metric.connectionsPercent=Math.min(100,100*metric.connections/metric.maxConnections);
 const hits=metric.keyspaceHits,misses=metric.keyspaceMisses;if(hits!==undefined&&misses!==undefined&&hits+misses>0)metric.cacheHitPercent=100*hits/(hits+misses);
 const db=Number(config.database||'0');if(!Number.isInteger(db)||db<0||db>65535)throw new DatabaseReadError('INVALID_DATABASE');const keys=data.get('db'+db)?.match(/(?:^|,)keys=(\d+)(?:,|$)/);if(keys)metric.keyCount=counter(keys[1]);
 metric.issues=['SQL_METRICS_NOT_APPLICABLE',...(maxMemory===0?['MEMORY_LIMIT_UNSET']:[]),...(!keys?['KEY_COUNT_UNAVAILABLE']:[])];return genericDatabaseMetricInput.parse(metric);
}
export async function readRedisMetrics(config:DatabaseRuntimeConfig,password:string,configurationVersion:number,previous?:GenericDatabaseMetric):Promise<GenericDatabaseMetric>{
 config=databaseRuntimeInput.parse(config);
 const started=performance.now(),client=createClient({username:config.username||undefined,password,disableClientInfo:true,socket:{host:config.address,port:config.port,connectTimeout:3000,reconnectStrategy:false,...(config.tls?{tls:true as const,rejectUnauthorized:true,...(isIP(config.address)?{}:{servername:config.address}),checkServerIdentity:(_hostname:string,certificate:Parameters<typeof checkServerIdentity>[1])=>checkServerIdentity(config.address,certificate),...(config.caCertificate?{ca:config.caCertificate}:{})}:{})},commandsQueueMaxLength:2});
 // Error events are consumed; the awaited command reports a sanitized failure to the monitor.
 client.on('error',()=>{});let timer:ReturnType<typeof setTimeout>|undefined;
 try{const metric=await Promise.race([ (async()=>{await client.connect();const info=await client.info();return parseRedisInfo(info,config,configurationVersion,performance.now()-started)})(),new Promise<never>((_,reject)=>{timer=setTimeout(()=>{if(client.isOpen)client.destroy();reject(new DatabaseReadError('QUERY_TIMEOUT'))},8000)})]);return{...metric,...databaseRates(previous,metric)};}finally{if(timer)clearTimeout(timer);if(client.isOpen)client.destroy();}
}
export async function readMysqlMetrics(config:DatabaseRuntimeConfig,password:string,configurationVersion:number,previous?:GenericDatabaseMetric):Promise<GenericDatabaseMetric>{
 config=databaseRuntimeInput.parse(config);
 // mysql2 skips its explicit identity check for literal IPs. Fail before authentication.
 if(config.tls&&isIP(config.address))throw new DatabaseReadError('MYSQL_TLS_DNS_REQUIRED');
 const started=performance.now(),client=mysql.createConnection({host:config.address,port:config.port,user:config.username,password,database:config.database||undefined,connectTimeout:3000,multipleStatements:false,insecureAuth:false,ssl:config.tls?{rejectUnauthorized:true,verifyIdentity:true,...(config.caCertificate?{ca:config.caCertificate}:{})}:undefined});
 let timer:ReturnType<typeof setTimeout>|undefined;
 try{const metric=await Promise.race([(async()=>{const connection=client.promise();const[identity]=await connection.query<RowDataPacket[]>({sql:'SELECT @@version AS version, @@version_comment AS product, @@server_uuid AS identity, @@max_connections AS maxConnections',timeout:3000});const r=identity[0];if(!r||!/mysql/i.test(String(r.product))||!/^(5\.7\.|8\.[04]\.)/.test(String(r.version))||/mariadb|tidb|oceanbase/i.test(String(r.version)+' '+String(r.product)))throw new DatabaseReadError('UNSUPPORTED_VERSION');
 const[status]=await connection.query<RowDataPacket[]>({sql:"SHOW GLOBAL STATUS WHERE Variable_name IN ('Threads_connected','Threads_running','Com_commit','Com_rollback','Innodb_deadlocks','Innodb_buffer_pool_read_requests','Innodb_buffer_pool_reads','Uptime')",timeout:3000});
 if(status.length>16||Buffer.byteLength(JSON.stringify(status))>maxOutput)throw new DatabaseReadError('OUTPUT_LIMIT');const data=new Map(status.map(row=>[String(row.Variable_name),row.Value]));
 const metric:GenericDatabaseMetric=base('mysql',String(r.version),config,configurationVersion,performance.now()-started,String(r.identity));
 metric.maxConnections=counter(r.maxConnections);for(const[source,target]of [['Threads_connected','connections'],['Threads_running','active'],['Com_commit','commits'],['Com_rollback','rollbacks'],['Innodb_deadlocks','deadlocks'],['Uptime','uptimeSeconds']]as const){const n=counter(data.get(source));if(n!==undefined)metric[target]=n;}
 if(metric.maxConnections&&metric.connections!==undefined)metric.connectionsPercent=Math.min(100,100*metric.connections/metric.maxConnections);const hits=counter(data.get('Innodb_buffer_pool_read_requests')),misses=counter(data.get('Innodb_buffer_pool_reads'));if(hits!==undefined&&misses!==undefined&&hits>0)metric.cacheHitPercent=Math.max(0,100*(1-misses/hits));metric.issues=['LOCK_AND_QUERY_METRICS_UNAVAILABLE','DATABASE_SIZE_UNAVAILABLE'];return genericDatabaseMetricInput.parse(metric)})(),new Promise<never>((_,reject)=>{timer=setTimeout(()=>{client.destroy();reject(new DatabaseReadError('QUERY_TIMEOUT'))},8000)})]);return{...metric,...databaseRates(previous,metric)};}finally{if(timer)clearTimeout(timer);client.destroy();}
}
