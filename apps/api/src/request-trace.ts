import {z} from 'zod';
export const requestTraceInput=z.object({
 requestId:z.string().min(1).max(500),peerIp:z.string().max(100),peerPort:z.string().max(10).optional(),clientIp:z.string().max(100),
 sourceBasis:z.enum(['SOCKET_PEER','TRUSTED_PROXY_CHAIN']),incomingTls:z.boolean(),requestTargetSha256:z.string().regex(/^[a-f0-9]{64}$/),
 pathRetention:z.literal('SANITIZED_PATH_QUERY_VALUES_NOT_RETAINED'),queryKeys:z.array(z.string().max(80)).max(30),queryKeysOmitted:z.number().int().min(0),
 configuredUpstream:z.string().url().max(2048).refine(value=>{const u=new URL(value);return ['http:','https:'].includes(u.protocol)&&!u.username&&!u.password&&!u.search&&!u.hash&&u.pathname==='/'}).optional(),
 upstreamAddress:z.string().max(253).optional(),upstreamTls:z.boolean().optional(),forwarded:z.boolean(),action:z.enum(['ALLOW','BLOCK','OBSERVE']),ruleId:z.string().max(100).optional(),
 outcome:z.enum(['NOT_FORWARDED','BLOCKED_BY_WAF','UPSTREAM_RESPONSE','UPSTREAM_ERROR']),banState:z.literal('NO_PERSISTENT_BAN')
}).strict();
