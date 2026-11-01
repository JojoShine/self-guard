import {z} from 'zod';
export const databaseChecks=['MYSQL_TLS_REQUIRED','POSTGRES_TLS_ENABLED','POSTGRES_HBA_TLS','POSTGRES_HBA_AUTH','CREDENTIAL_FILE_MODE'] as const;
export const databaseBaselineInput=z.object({type:z.literal('DATABASE_SECURITY'),path:z.string().startsWith('/').max(4096),key:z.enum(databaseChecks)}).strict();
export const databaseLogInput=z.object({type:z.enum(['DATABASE_AUTH','DATABASE_CLEARTEXT']),path:z.string().startsWith('/').max(4096),service:z.enum(['mysql','postgresql','audit-json']),threshold:z.number().int().min(1).max(1000),windowSeconds:z.number().int().min(1).max(86400)}).strict().refine(v=>v.type!=='DATABASE_CLEARTEXT'||(v.service==='audit-json'&&v.threshold===1),'明文连接需要显式连接审计，阈值为1');
export function requiresDataSecurity(config:any){return ['DATABASE_SECURITY','DATABASE_AUTH','DATABASE_CLEARTEXT'].includes(config?.type);}
export const databaseRuleCatalog=[
 {id:'auth',name:'数据库疑似口令爆破',kind:'LOG',severity:'HIGH',type:'DATABASE_AUTH',description:'按数据库实例日志路径和来源IP聚合原始发生时间内的认证失败，覆盖同源多账号尝试；不会自动封禁。',formats:['mysql','postgresql','audit-json']},
 {id:'plaintext',name:'数据库未加密连接',kind:'LOG',severity:'HIGH',type:'DATABASE_CLEARTEXT',description:'只对成功连接且明确报告tls=false的审计记录告警；缺失加密字段、登录失败或端口开放不作为明文传输证据。',formats:['audit-json']},
 {id:'mysql-tls',name:'MySQL未强制加密连接',kind:'BASELINE',severity:'HIGH',type:'DATABASE_SECURITY',key:'MYSQL_TLS_REQUIRED',description:'检查服务端配置段require_secure_transport是否启用；包含外部配置或键重复时标为无法完整检查，文件配置不证明实例运行状态。'},
 {id:'pg-tls',name:'PostgreSQL未启用TLS',kind:'BASELINE',severity:'HIGH',type:'DATABASE_SECURITY',key:'POSTGRES_TLS_ENABLED',description:'检查postgresql.conf的ssl设置，仅反映文件配置。启用TLS仍需同时检查pg_hba是否允许未加密连接。'},
 {id:'pg-hba-tls',name:'PostgreSQL存在允许非加密连接的配置',kind:'BASELINE',severity:'HIGH',type:'DATABASE_SECURITY',key:'POSTGRES_HBA_TLS',description:'检查pg_hba中的host、hostnossl等允许规则，排除reject、Unix socket和明确加密规则；不推断规则实际可达性。'},
 {id:'pg-hba-auth',name:'PostgreSQL网络免认证配置',kind:'BASELINE',severity:'HIGH',type:'DATABASE_SECURITY',key:'POSTGRES_HBA_AUTH',description:'识别网络连接trust认证配置；不把本地socket认证当作远程免认证。'},
 {id:'credential-mode',name:'数据库凭据文件权限过宽',kind:'BASELINE',severity:'MEDIUM',type:'DATABASE_SECURITY',key:'CREDENTIAL_FILE_MODE',description:'检查指定凭据文件是否向属组或其他用户开放权限；0400、0600等更严格权限允许，不读取或展示凭据内容。'}
];
