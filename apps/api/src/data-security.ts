import {engines,operations} from './database-contract';
import {z} from 'zod';
export const databaseChecks=['MYSQL_TLS_REQUIRED','POSTGRES_TLS_ENABLED','POSTGRES_HBA_TLS','POSTGRES_HBA_AUTH','CREDENTIAL_FILE_MODE'] as const;
export const databaseBaselineInput=z.object({type:z.literal('DATABASE_SECURITY'),path:z.string().startsWith('/').max(4096),instanceId:z.string().uuid().optional(),key:z.enum(databaseChecks)}).strict();
export const databaseLogInput=z.object({type:z.enum(['DATABASE_AUTH','DATABASE_CLEARTEXT']),path:z.string().startsWith('/').max(4096),service:z.enum(['mysql','postgresql','audit-json']),instanceId:z.string().uuid().optional(),threshold:z.number().int().min(1).max(1000),windowSeconds:z.number().int().min(1).max(86400)}).strict().refine(v=>v.type!=='DATABASE_CLEARTEXT'||(v.service==='audit-json'&&v.threshold===1),'明文连接需要显式连接审计，阈值为1');
export const databaseActivityInput=z.object({type:z.literal('DATABASE_ACTIVITY'),path:z.string().startsWith('/').max(4096),service:z.literal('audit-json'),instanceId:z.string().uuid(),minimumRows:z.number().int().min(1).optional(),requireSuccess:z.boolean().optional(),engines:z.array(z.enum(engines)).min(1).max(engines.length),operations:z.array(z.enum(operations)).min(1).max(operations.length),threshold:z.number().int().min(1).max(1000),windowSeconds:z.number().int().min(1).max(86400)}).strict();
export const databaseAccessInput=z.object({type:z.literal('DATABASE_ACCESS'),path:z.string().startsWith('/').max(4096),service:z.literal('audit-json'),instanceId:z.string().uuid(),engines:z.array(z.enum(engines)).min(1).max(engines.length),detectPermissionDenied:z.boolean().default(false),allowUsers:z.array(z.string().trim().min(1).max(128)).max(100).default([]),allowSources:z.array(z.string().max(100).refine(value=>{const [ip,prefix]=value.split('/');const version=require('node:net').isIP(ip);return !!version&&(prefix===undefined||(/^\d+$/.test(prefix)&&Number(prefix)<=(version===6?128:32)))})).max(100).default([]),allowedHours:z.array(z.number().int().min(0).max(23)).max(24).default([]),timeZone:z.string().max(100).refine(value=>{try{new Intl.DateTimeFormat('en',{timeZone:value});return true}catch{return false}}).default('UTC'),threshold:z.number().int().min(1).max(1000),windowSeconds:z.number().int().min(1).max(86400)}).strict().refine(v=>v.detectPermissionDenied||v.allowUsers.length+v.allowSources.length+v.allowedHours.length>0,'至少配置一项准入基线');
export function requiresDataSecurity(config:any){return ['DATABASE_SECURITY','DATABASE_AUTH','DATABASE_CLEARTEXT','DATABASE_ACTIVITY','DATABASE_ACCESS'].includes(config?.type);}
const admissionCatalog=[
 {id:'permission-denied',name:'数据库鉴权拒绝',kind:'LOG',severity:'HIGH',type:'DATABASE_ACCESS',detectPermissionDenied:true,description:'仅依据原生审计明确报告的权限检查失败；不把语法错误、未知结果或一般执行失败认定为越权。',formats:['audit-json']},
 {id:'access-baseline',name:'数据库准入基线偏离',kind:'LOG',severity:'HIGH',type:'DATABASE_ACCESS',description:'仅对明确成功登录的账号、来源或时段偏离进行检测，缺失来源时不推断越权。',formats:['audit-json']},
 {id:'auth',name:'数据库疑似口令爆破',kind:'LOG',severity:'HIGH',type:'DATABASE_AUTH',description:'按数据库实例日志路径和来源IP聚合原始发生时间内的认证失败，覆盖同源多账号尝试；不会自动封禁。',formats:['mysql','postgresql','audit-json']},
 {id:'plaintext',name:'数据库未加密连接',kind:'LOG',severity:'HIGH',type:'DATABASE_CLEARTEXT',description:'只对成功连接且明确报告tls=false的审计记录告警；缺失加密字段、登录失败或端口开放不作为明文传输证据。',formats:['audit-json']},
 {id:'mysql-tls',name:'MySQL未强制加密连接',kind:'BASELINE',severity:'HIGH',type:'DATABASE_SECURITY',key:'MYSQL_TLS_REQUIRED',description:'检查服务端配置段require_secure_transport是否启用；包含外部配置或键重复时标为无法完整检查，文件配置不证明实例运行状态。'},
 {id:'pg-tls',name:'PostgreSQL未启用TLS',kind:'BASELINE',severity:'HIGH',type:'DATABASE_SECURITY',key:'POSTGRES_TLS_ENABLED',description:'检查postgresql.conf的ssl设置，仅反映文件配置。启用TLS仍需同时检查pg_hba是否允许未加密连接。'},
 {id:'pg-hba-tls',name:'PostgreSQL存在允许非加密连接的配置',kind:'BASELINE',severity:'HIGH',type:'DATABASE_SECURITY',key:'POSTGRES_HBA_TLS',description:'检查pg_hba中的host、hostnossl等允许规则，排除reject、Unix socket和明确加密规则；不推断规则实际可达性。'},
 {id:'pg-hba-auth',name:'PostgreSQL网络免认证配置',kind:'BASELINE',severity:'HIGH',type:'DATABASE_SECURITY',key:'POSTGRES_HBA_AUTH',description:'识别网络连接trust认证配置；不把本地socket认证当作远程免认证。'},
 {id:'credential-mode',name:'数据库凭据文件权限过宽',kind:'BASELINE',severity:'MEDIUM',type:'DATABASE_SECURITY',key:'CREDENTIAL_FILE_MODE',description:'检查指定凭据文件是否向属组或其他用户开放权限；0400、0600等更严格权限允许，不读取或展示凭据内容。'}
];

export const databaseEngineCatalog=[
 {id:'oracle',name:'Oracle',source:'https://docs.oracle.com/en/database/oracle/oracle-database/19/dbseg/introduction-to-auditing.html',versions:'11g、12c及以上',format:'11g传统审计与12c+统一审计视图逐条JSON导出；标准审计JSON'},
 {id:'mysql',name:'MySQL',source:'https://dev.mysql.com/doc/refman/8.4/en/audit-log-file-formats.html',versions:'5.7、8.x',format:'认证错误日志；Audit Log逐条JSON导出；标准审计JSON'},
 {id:'postgresql',name:'PostgreSQL',source:'https://www.postgresql.org/docs/current/runtime-config-logging.html',versions:'14及以上',format:'14+ pgAudit CSV；15+ pgAudit jsonlog；标准审计JSON'},
 {id:'sqlserver',name:'SQL Server',source:'https://learn.microsoft.com/en-us/sql/relational-databases/security/auditing/sql-server-audit-records',versions:'2022兼容目标，待确认',format:'SQL Server Audit视图逐条JSON导出；标准审计JSON'},
 {id:'dm',name:'达梦',source:'https://eco.dameng.com/document/dm/zh-cn/pm/audit.html',versions:'DM8常规版本',format:'DM8官方dmaudtool不可变审计快照元数据JSON导出；标准审计JSON'},
 {id:'kingbase',name:'金仓',source:'https://help.kingbase.com.cn/v9.3.11/PDF/KingbaseES安全指南.pdf',versions:'V8/V9常规版本',format:'标准审计JSON，原生导出适配待实库核对'}
];
export const databaseRuleCatalog=[
 ...admissionCatalog.map(row=>({...row,category:'ADMISSION',engines:row.id.startsWith('mysql')?['mysql']:row.id.startsWith('pg-')?['postgresql']: [...engines],operations:[] as string[]})),
 ...databaseEngineCatalog.flatMap(engine=>[
  {id:engine.id+'-read',name:engine.name+'数据读取与导出',kind:'LOG',severity:'MEDIUM',type:'DATABASE_ACTIVITY',category:'BEHAVIOR',engines:[engine.id],formats:['audit-json'],operations:['SELECT','EXPORT'],description:'记录明确审计的数据读取/导出元数据，以分类分级定义提升风险等级；不采集SQL正文和数据值。',key:undefined},
  {id:engine.id+'-write',name:engine.name+'数据修改与结构变更',kind:'LOG',severity:'HIGH',type:'DATABASE_ACTIVITY',category:'BEHAVIOR',engines:[engine.id],formats:['audit-json'],operations:['INSERT','UPDATE','DELETE','DDL'],description:'按审计中的操作与对象检测数据及结构变更，钻取至实例、模式、表和账号。',key:undefined},
  {id:engine.id+'-privilege',name:engine.name+'权限与审计变更',kind:'LOG',severity:'HIGH',type:'DATABASE_ACTIVITY',category:'BEHAVIOR',engines:[engine.id],formats:['audit-json'],operations:['GRANT','REVOKE','AUDIT_DISABLE'],description:'检测明确报告的授权、撤权和停用审计操作；操作结果由原始审计提供，不推断越权或执行成功。',key:undefined}
 ])
];
