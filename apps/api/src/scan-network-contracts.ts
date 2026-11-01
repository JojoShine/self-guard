import {z} from 'zod';
const text=(maximum:number)=>z.string().max(maximum).refine(value=>Buffer.byteLength(value)<=maximum,'内容超过允许的字节数，请缩短');
export const networkKinds=['TCP_CONNECT','TCP_BANNER','TLS_HANDSHAKE','TLS_CERT_EXPIRED','TLS_CERT_EXPIRING','TLS_WEAK_PROTOCOL'] as const;
export const networkRule=z.object({id:text(200).refine(value=>value.length>0),description:text(2000).refine(value=>value.length>0),kind:z.enum(networkKinds),value:text(512).optional(),days:z.number().int().min(0).max(365).optional()}).strict().refine(value=>{
 const empty=!value.value,zero=!value.days;
 switch(value.kind){case'TCP_CONNECT':case'TLS_HANDSHAKE':case'TLS_CERT_EXPIRED':return empty&&zero;case'TCP_BANNER':return !!value.value&&zero;case'TLS_CERT_EXPIRING':return empty&&!!value.days;case'TLS_WEAK_PROTOCOL':return ['TLS1.0','TLS1.1'].includes(value.value||'')&&zero}
},'检查类型与参数不匹配：服务特征需填写明确文本，到期天数为1–365，弱协议只接受TLS1.0或TLS1.1');
export const networkDefinition=z.object({kind:z.literal('NETWORK'),protocol:z.enum(['tcp','tls']),rule:networkRule}).strict().refine(value=>value.rule.kind.startsWith(value.protocol.toUpperCase()+'_'),'目标协议和检查类型不一致，请分别选择TCP或TLS检查');
export const networkSample=z.object({name:z.string().trim().min(1).max(100),expectedMatched:z.boolean(),connected:z.boolean(),banner:text(4096).optional(),tlsVersion:z.enum(['TLS1.0','TLS1.1','TLS1.2','TLS1.3']).optional(),observedAt:z.iso.datetime({offset:true}).optional(),notBefore:z.iso.datetime({offset:true}).optional(),notAfter:z.iso.datetime({offset:true}).optional()}).strict();
export const networkSamples=z.array(networkSample).min(2).max(8).refine(values=>values.some(row=>row.expectedMatched)&&values.some(row=>!row.expectedMatched),'至少提供一个应命中和一个应不命中的完整观察样本');
const certificate=z.object({verified:z.boolean(),version:z.string().max(100).optional(),cipherSuite:z.string().max(200).optional(),certificateSha256:z.string().regex(/^[a-f0-9]{64}$/),subject:z.string().max(1000),notBefore:z.iso.datetime({offset:true}),notAfter:z.iso.datetime({offset:true}),certificateRole:z.literal('LEAF')}).strict();
const connection=z.object({source:z.string().min(1).max(128),destination:z.string().min(1).max(128),transport:z.literal('TCP')}).strict();
export const networkProof=z.object({ruleId:text(200).refine(value=>value.length>0),description:text(2000).refine(value=>value.length>0),checkKind:z.enum(networkKinds),hostname:z.string().min(1).max(253),port:z.number().int().min(1).max(65535),protocol:z.enum(['tcp','tls']),startedAt:z.iso.datetime({offset:true}),durationMs:z.number().int().min(0).max(15000),connections:z.array(connection).max(1).optional(),connectedPeers:z.array(z.string().min(1).max(128)).max(1).optional(),bannerSha256:z.string().regex(/^[a-f0-9]{64}$/).optional(),bannerBytes:z.number().int().min(0).max(4096).optional(),bannerPreview:z.string().max(2048).refine(value=>Buffer.byteLength(value)<=4096).optional(),tls:certificate.optional(),validationReason:z.enum(['TLS_HOSTNAME_MISMATCH','TLS_CERTIFICATE_INVALID','TLS_CERTIFICATE_EXPIRED','TLS_CERTIFICATE_NOT_YET_VALID','TLS_CERTIFICATE_UNTRUSTED']).optional()}).strict();
export const networkResult=z.object({outcome:z.enum(['OBSERVED','CONFIRMED','NOT_FOUND','INCONCLUSIVE']),reason:z.string().regex(/^[A-Z_]+$/).max(100).optional(),evidence:networkProof}).strict().superRefine((value,ctx)=>{
 const proof=value.evidence,observe=['TCP_CONNECT','TLS_HANDSHAKE'].includes(proof.checkKind),complete=value.outcome!=='INCONCLUSIVE';
 const invalid=(message:string)=>ctx.addIssue({code:'custom',message});
 if(!proof.checkKind.startsWith(proof.protocol.toUpperCase()+'_'))invalid('网络证据协议不一致');
 if(complete){if(proof.connections?.length!==1||proof.connectedPeers?.length!==1||proof.connectedPeers[0]!==proof.connections[0].destination)invalid('缺少一致的实际连接方向');if(observe!== (value.outcome==='OBSERVED'))invalid('连通或握手观察不能标记为漏洞');if(proof.protocol==='tls'&&!proof.tls)invalid('缺少实际TLS证书');if(proof.checkKind==='TCP_BANNER'&&(!proof.bannerSha256||!proof.bannerBytes||!proof.bannerPreview))invalid('缺少实际服务特征')}
 if(proof.protocol==='tcp'&&(proof.tls||proof.validationReason))invalid('TCP证据混入TLS字段');
 if(proof.tls&&(proof.tls.verified?!!proof.validationReason:!proof.validationReason))invalid('证书信任状态和原因不一致');
});
export type NetworkDefinition=z.infer<typeof networkDefinition>;
export type NetworkResult=z.infer<typeof networkResult>;
export function compatibleProbe(definition:{kind?:string;protocol?:string;method?:string},protocol:string){return definition.kind==='NETWORK'?definition.protocol===protocol:['http','https'].includes(protocol)}
