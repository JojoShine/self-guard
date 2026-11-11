import {z} from 'zod';
const timestamp=z.iso.datetime({offset:true});
const hash=z.string().regex(/^[a-f0-9]{64}$/);
const counter=z.string().regex(/^(0|[1-9][0-9]{0,19})$/);
const flowId=z.string().regex(/^[0-9]{1,20}$/).refine(v=>/^[0-9]{1,20}$/.test(v)&&BigInt(v)<=18446744073709551615n,'flow ID 超出 uint64 范围');
const port=z.number().int().min(0).max(65535);
const count=z.number().int().min(0).max(Number.MAX_SAFE_INTEGER);
const ip=z.union([z.ipv4(),z.ipv6()]);
const path=z.string().min(2).max(1024).regex(/^\/(?:[^\x00-\x1f\x7f]+)$/).refine(v=>!v.split('/').some(part=>part==='.'||part==='..'),'路径不可包含相对目录');
const httpsURL=z.string().url().max(1024).refine(value=>{try{const u=new URL(value);return u.protocol==='https:'&&!u.username&&!u.password&&!u.search&&!u.hash}catch{return false}},'规则来源需要不含凭据或查询串的HTTPS地址');
export const networkSensorInput=z.object({name:z.string().trim().min(1).max(160),assetId:z.string().uuid(),evePath:path.default('/var/log/suricata/eve.json'),enabled:z.boolean().default(false),engineVersion:z.string().max(64).default(''),ruleFile:path.optional(),ruleSetName:z.string().max(160).default(''),ruleSetVersion:z.string().max(96).default(''),ruleSourceUrl:httpsURL.optional(),expectedRuleSha256:hash.optional(),updateEveryHours:z.number().int().min(1).max(720).default(24)}).strict();
export const networkSensorPatch=networkSensorInput.omit({assetId:true}).partial().extend({evePath:path.optional(),enabled:z.boolean().optional(),engineVersion:z.string().max(64).optional(),ruleSetName:z.string().max(160).optional(),ruleSetVersion:z.string().max(96).optional(),updateEveryHours:z.number().int().min(1).max(720).optional(),ruleFile:path.nullable().optional(),ruleSourceUrl:httpsURL.nullable().optional(),expectedRuleSha256:hash.nullable().optional(),expectedUpdatedAt:timestamp}).strict();
export const networkMetadataInput=z.object({
 alert:z.object({signatureId:z.number().int().min(0).max(4294967295),gid:z.number().int().min(0).max(4294967295),rev:z.number().int().min(0).max(4294967295),severity:z.number().int().min(0).max(255),signature:z.string().max(500),category:z.string().max(200).optional(),action:z.enum(['allowed','blocked','rejected','unknown'])}).strict().optional(),
 http:z.object({hostname:z.string().max(253).optional(),method:z.string().max(32).optional(),path:z.string().max(1024).refine(v=>!v.includes('?')&&!v.includes('#'),'接口路径不得包含查询串或片段').optional(),status:z.number().int().min(100).max(599).optional()}).strict().optional(),
 dns:z.object({names:z.array(z.string().max(253)).max(16),rrtype:z.string().max(32).optional(),rcode:z.string().max(32).optional()}).strict().optional(),
 tls:z.object({sni:z.string().max(253).optional(),version:z.string().max(32).optional(),subject:z.string().max(512).optional(),issuer:z.string().max(512).optional(),fingerprint:z.string().max(128).optional()}).strict().optional(),
 flow:z.object({pktsToServer:counter.optional(),pktsToClient:counter.optional(),bytesToServer:counter.optional(),bytesToClient:counter.optional(),state:z.string().max(48).optional(),reason:z.string().max(80).optional(),alerted:z.boolean().optional()}).strict().optional(),
 anomaly:z.object({type:z.string().max(80).optional(),event:z.string().max(200).optional()}).strict().optional(),
 stats:z.object({uptime:count.optional(),kernelPackets:counter.optional(),kernelDrops:counter.optional(),decoderPackets:counter.optional(),decoderBytes:counter.optional(),alertsSuppressed:counter.optional(),alertQueueOverflow:counter.optional(),rulesLoaded:count.optional(),rulesFailed:count.optional(),rulesSkipped:count.optional()}).strict().optional(),
}).strict();
export const networkEventInput=z.object({eventId:hash,sourceSha256:hash,occurredAt:timestamp,eventType:z.enum(['alert','http','dns','tls','flow','anomaly','stats']),flowId:flowId.optional(),sourceIp:ip.optional(),destinationIp:ip.optional(),sourcePort:port.optional(),destinationPort:port.optional(),protocol:z.string().max(16).optional(),appProtocol:z.string().max(48).optional(),metadata:networkMetadataInput}).strict().superRefine((event,ctx)=>{if(!event.metadata[event.eventType])ctx.addIssue({code:'custom',message:'事件类型与元数据不一致'});});
export const networkHealthInput=z.object({status:z.enum(['READING','WAITING','ERROR']),detailCode:z.enum(['OK','WAITING_FOR_EVE','READ_ERROR','INVALID_EVE','ROTATION_GAP','QUEUE_BLOCKED','RULE_FILE_UNAVAILABLE']).default('OK'),observedAt:timestamp,invalidLines:count,skippedLines:count,rotationGaps:count,pendingEvents:count,rulesSha256:hash.optional(),rulesModifiedAt:timestamp.optional()}).strict();
export const networkBatchInput=z.object({batchId:z.string().uuid(),mode:z.enum(['LIVE','REPLAY']),events:z.array(networkEventInput).max(50),health:networkHealthInput}).strict();
export type NetworkEvent=z.infer<typeof networkEventInput>;
export type NetworkBatch=z.infer<typeof networkBatchInput>;
export const networkEventQuery=z.object({sensorId:z.string().uuid().optional(),assetId:z.string().uuid().optional(),eventType:z.enum(['alert','http','dns','tls','flow','anomaly','stats']).optional(),flowId:flowId.optional(),from:timestamp.optional(),to:timestamp.optional(),page:z.coerce.number().int().min(1).default(1),pageSize:z.coerce.number().int().min(1).max(100).default(20)}).strict().refine(v=>!v.from||!v.to||Date.parse(v.from)<=Date.parse(v.to),'开始时间不得晚于结束时间');
