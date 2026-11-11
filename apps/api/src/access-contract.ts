import {BadRequestException,GoneException} from '@nestjs/common';
import {z} from 'zod';
import {databaseObjectInput} from './database-contract';
import {postgresRelationInput} from './access-classification';

export const accessProtocols=['HTTP','MYSQL','POSTGRESQL','REDIS','ORACLE','SQLSERVER','DM','KINGBASE'] as const;
export const accessGapCodes=['CAPTURE_LOSS','MIDSTREAM','TLS_NO_PLAINTEXT','PROTOCOL_UNSUPPORTED','PARSE_ERROR','DISCONNECTED','RESOURCE_LIMIT','QUEUE_FULL','PROBE_STOPPED','BODY_NOT_CAPTURED','CORRELATION_UNKNOWN','EVIDENCE_EXPIRED','PROBE_PROFILE_MISMATCH'] as const;
export const opensslProfileInput=z.object({kind:z.literal('OPENSSL_DYNAMIC'),libraryPath:z.string().regex(/^\/[a-zA-Z0-9_./+-]+$/).max(1024),pid:z.number().int().min(1).max(4194304),uid:z.number().int().min(0).max(2147483647),startTicks:z.string().regex(/^[1-9][0-9]{0,19}$/),executableSha256:z.string().regex(/^[a-f0-9]{64}$/),librarySha256:z.string().regex(/^[a-f0-9]{64}$/),executableIdentity:z.string().regex(/^\d+:\d+:\d+:\d+:\d+$/).max(200),libraryIdentity:z.string().regex(/^\d+:\d+:\d+:\d+:\d+$/).max(200)}).strict();
export const probeHealthInput=z.object({state:z.enum(['STARTING','RUNNING','DEGRADED','STOPPED','FAILED']),version:z.string().max(64),capturedPackets:z.number().int().min(0),droppedPackets:z.number().int().min(0).nullable(),queueBytes:z.number().int().min(0),pendingEvents:z.number().int().min(0),rejectedEvents:z.number().int().min(0).optional(),gap:z.enum(['NONE',...accessGapCodes]),configurationVersion:z.number().int().min(1)}).strict();
const time=z.string().datetime({offset:true});
const size=z.number().int().min(0).max(Number.MAX_SAFE_INTEGER);
export const chunkDescriptor=z.object({direction:z.enum(['REQUEST','RESPONSE','PACKET']),sequence:z.number().int().min(0).max(65535),capturedAt:time,sha256:z.string().regex(/^[a-f0-9]{64}$/),bytes:size.min(1).max(262144)}).strict();
export const accessChunkInput=chunkDescriptor.omit({bytes:true}).extend({eventId:z.string().uuid(),data:z.string().min(4).max(349528).refine(v=>/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(v)&&Buffer.from(v,'base64').length<=262144,'证据分段无效')}).strict();
export const accessEventInput=z.object({
 eventId:z.string().uuid(),startedAt:time,endedAt:time,sessionId:z.string().min(1).max(128),operation:z.string().regex(/^[A-Z][A-Z0-9_]{0,31}$/),
 route:z.string().startsWith('/').max(2048).refine(v=>!/[?#\r\n\x00]/.test(v),'路径索引不保留查询参数').optional(),
 sourceIp:z.union([z.ipv4(),z.ipv6()]).optional(),sourcePort:z.number().int().min(0).max(65535).optional(),
 databaseUser:z.string().min(1).max(128).optional(),database:z.string().min(1).max(128).optional(),
 authentication:z.enum(['SUCCESS','FAILURE','UNKNOWN']).default('UNKNOWN'),permission:z.enum(['GRANTED','DENIED','UNKNOWN']).default('UNKNOWN'),
 result:z.enum(['SUCCESS','FAILURE','UNKNOWN']),transaction:z.enum(['COMMITTED','ROLLED_BACK','UNKNOWN']).default('UNKNOWN'),statusCode:z.number().int().min(100).max(599).optional(),tls:z.boolean().optional(),
 completeness:z.enum(['COMPLETE','PARTIAL','UNSUPPORTED']),gaps:z.array(z.enum(accessGapCodes)).max(12),
 requestBytes:size,responseBytes:size,rows:size.optional(),objects:z.array(databaseObjectInput).max(32).default([]),relations:z.array(postgresRelationInput).max(128).optional(),chunks:z.array(chunkDescriptor).max(8192),
 fragments:z.array(z.object({offset:size,bytes:size.max(16384),callId:z.string().regex(/^[0-9]{1,20}$/)}).strict()).max(256).optional(),
}).strict().superRefine((v,ctx)=>{
 if(Date.parse(v.endedAt)<Date.parse(v.startedAt))ctx.addIssue({code:'custom',message:'访问结束时间早于开始时间'});
 if(v.completeness==='COMPLETE'&&v.gaps.length)ctx.addIssue({code:'custom',message:'存在缺口不能标为完整'});
 if(v.completeness!=='COMPLETE'&&!v.gaps.length)ctx.addIssue({code:'custom',message:'不完整记录必须说明缺口'});
 const keys=v.chunks.map(c=>c.direction+':'+c.sequence);if(new Set(keys).size!==keys.length)ctx.addIssue({code:'custom',message:'分段序号重复'});
 for(const direction of ['REQUEST','RESPONSE','PACKET']){
  const parts=v.chunks.filter(c=>c.direction===direction).sort((a,b)=>a.sequence-b.sequence);
  if(parts.some((c,i)=>c.sequence!==i))ctx.addIssue({code:'custom',message:'证据分段不连续'});
  if(direction!=='PACKET'){
   const bytes=parts.reduce((sum,c)=>sum+c.bytes,0),expected=direction==='REQUEST'?v.requestBytes:v.responseBytes;
   if(bytes>expected||(v.completeness==='COMPLETE'&&bytes!==expected))ctx.addIssue({code:'custom',message:'分段字节与访问证据长度不符'});
  }
 }
});
export type AccessEvent=z.infer<typeof accessEventInput>;
export type EvidenceBinding={sourceId:string;eventId:string;direction:string;sequence:number;capturedAt:string;sha256:string};
export function evidenceExpiresAt(capturedAt:Date){return new Date(capturedAt.getTime()+7*86400000);}
export function assertEvidenceLive(capturedAt:Date,now=new Date()){
 if(!Number.isFinite(capturedAt.getTime())||capturedAt.getTime()>now.getTime()+300000)throw new BadRequestException('证据捕获时间无效');
 if(evidenceExpiresAt(capturedAt)<=now)throw new GoneException('原始证据已到期');
}
