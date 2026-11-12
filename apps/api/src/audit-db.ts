import {Db} from './db';
export const AUDIT_DB=Symbol('AUDIT_DB');
type AuditEnvironment={DATABASE_URL?:string;AUDIT_DATABASE_URL?:string};
const allowedParameters=new Set(['schema','connection_limit','pool_timeout','connect_timeout','sslmode','sslaccept','sslcert','application_name']);
export function auditDatabaseUrl(environment:AuditEnvironment):string|undefined{
 if(!environment.AUDIT_DATABASE_URL)return undefined;
 try{
  const audit=new URL(environment.AUDIT_DATABASE_URL),runtime=new URL(environment.DATABASE_URL||'');
  if(!['postgres:','postgresql:'].includes(audit.protocol)||!['postgres:','postgresql:'].includes(runtime.protocol))throw Error();
  if(audit.hostname!==runtime.hostname||(audit.port||'5432')!==(runtime.port||'5432')||decodeURIComponent(audit.pathname)!==decodeURIComponent(runtime.pathname)||(audit.searchParams.get('schema')||'public')!==(runtime.searchParams.get('schema')||'public'))throw Error();
  if(decodeURIComponent(audit.username)!=='selfguard_sql_ingest'||!audit.password||decodeURIComponent(runtime.username)==='selfguard_sql_ingest'||audit.hash)throw Error();
  for(const key of audit.searchParams.keys())if(!allowedParameters.has(key)||audit.searchParams.getAll(key).length!==1)throw Error();
  if(audit.searchParams.get('sslmode')!=='require'||audit.searchParams.get('sslaccept')!=='strict')throw Error();
  const limit=audit.searchParams.get('connection_limit');if(limit&&!/^[12]$/.test(limit))throw Error();
  audit.searchParams.set('connection_limit',limit||'2');
  return audit.toString();
 }catch{throw new Error('AUDIT_DATABASE_URL must use the same database and schema, the isolated ingestion role, and strict TLS');}
}
type Boundary={sessionUser:string;currentUser:string;database:string;schema:string;ssl:boolean;superuser:boolean;createRole:boolean;createDb:boolean;replication:boolean;bypassRls:boolean;inheritsRuntime:boolean;runtimeCanBecomeIngest:boolean;runtimeSuperuser:boolean;duration:string;statement:string;sampleDuration:string;transactionSample:string;logDuration:string;errorStatement:string};
export function assertAuditDatabaseBoundary(row:Boundary|undefined){
 if(!row||row.sessionUser!=='selfguard_sql_ingest'||row.currentUser!==row.sessionUser||!row.ssl||row.superuser||row.createRole||row.createDb||row.replication||row.bypassRls||!row.inheritsRuntime||row.runtimeCanBecomeIngest||row.runtimeSuperuser||row.duration!=='-1'||row.statement!=='none'||row.sampleDuration!=='-1'||Number(row.transactionSample)!==0||row.logDuration!=='off'||row.errorStatement!=='panic')throw new Error('Dedicated audit database role, TLS, inheritance, or logging isolation is not configured');
}
export async function createAuditDatabase(runtime:Db,environment:AuditEnvironment=process.env):Promise<Db>{
 const url=auditDatabaseUrl(environment);if(!url)return runtime;
 const db=new Db({datasources:{db:{url}}});
 try{
  const runtimeRole=decodeURIComponent(new URL(environment.DATABASE_URL!).username);
  const rows=await db.$queryRaw<Boundary[]>`SELECT session_user AS "sessionUser",current_user AS "currentUser",current_database() AS database,current_schema() AS schema,
   (SELECT ssl FROM pg_stat_ssl WHERE pid=pg_backend_pid()) AS ssl,
   rolsuper AS superuser,rolcreaterole AS "createRole",rolcreatedb AS "createDb",rolreplication AS replication,rolbypassrls AS "bypassRls",
   pg_has_role(current_user,${runtimeRole},'USAGE') AS "inheritsRuntime",pg_has_role(${runtimeRole},current_user,'MEMBER') AS "runtimeCanBecomeIngest",
   (SELECT rolsuper FROM pg_roles WHERE rolname=${runtimeRole}) AS "runtimeSuperuser",
   current_setting('log_min_duration_statement') AS duration,current_setting('log_statement') AS statement,
   current_setting('log_min_duration_sample') AS "sampleDuration",current_setting('log_transaction_sample_rate') AS "transactionSample",
   current_setting('log_duration') AS "logDuration",current_setting('log_min_error_statement') AS "errorStatement"
   FROM pg_roles WHERE rolname=current_user`;
  assertAuditDatabaseBoundary(rows[0]);return db;
 }catch{await db.$disconnect();throw new Error('Dedicated audit database connection could not verify its protected ingestion boundary');}
}
export const auditDatabaseProvider={provide:AUDIT_DB,inject:[Db],useFactory:createAuditDatabase};
