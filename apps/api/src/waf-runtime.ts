import {createHash,createPrivateKey,sign,verify,createPublicKey} from 'node:crypto';
import {readFileSync,statSync} from 'node:fs';
import {BadRequestException,ServiceUnavailableException} from '@nestjs/common';
import {z} from 'zod';

const filesInput=z.array(z.object({name:z.string(),source:z.string()}).strict()).max(200);
export const wafRuntimeSelectionInput=z.object({siteIds:z.array(z.string().uuid()).min(1).max(20).refine(ids=>new Set(ids).size===ids.length,'站点不能重复'),threshold:z.number().int().min(1).max(100).default(5),reason:z.string().trim().min(5).max(1000)}).strict();

function signingKey(){
 const path=process.env.WAF_RULE_SIGNING_KEY_FILE;
 if(!path)throw new ServiceUnavailableException('尚未配置独立的 WAF 规则签名密钥');
 try{const stat=statSync(path);if(!stat.isFile()||stat.size>4096||(stat.mode&0o077)!==0)throw Error();const encoded=readFileSync(path,'utf8').trim(),raw=Buffer.from(encoded,'base64');if(raw.toString('base64')!==encoded)throw Error();const key=createPrivateKey({key:raw,format:'der',type:'pkcs8'});if(key.asymmetricKeyType!=='ed25519')throw Error();return key;}catch{throw new ServiceUnavailableException('WAF 规则签名密钥无效或文件权限不符合要求');}
}
export function wafPublicTrustRoot(){
 if(!process.env.WAF_RULE_SIGNING_KEY_FILE)return '';
 const publicKey=createPublicKey(signingKey()).export({format:'jwk'});
 return Buffer.from(publicKey.x!,'base64url').toString('base64');
}
export function runtimeSite(site:any){return {id:site.id,name:site.name,hostname:site.hostname,upstream:site.upstream,mode:site.mode,enabled:site.enabled,version:site.version,config:site.config||{}};}
export function signWafRuntime(site:any,bundle:{id:string;sha256:string;files:unknown}|null,threshold:number){
 if(!Number.isInteger(threshold)||threshold<1||threshold>100)throw new BadRequestException('评分阈值需要为1至100');
 if(bundle&&((site.config?.maxBodyBytes??1048576)>1048576||site.config?.exceptions?.length))throw new BadRequestException('规则档位支持最多1 MiB正文；规则例外请通过派生规则包维护');
 const files=bundle?filesInput.parse(bundle.files).sort((a,b)=>a.name<b.name?-1:a.name>b.name?1:0):[],sha256=createHash('sha256').update(JSON.stringify(files)).digest('hex');
 if(bundle&&sha256!==bundle.sha256)throw new BadRequestException('规则内容与固定摘要不符，不能签发');
 const payload={schemaVersion:1,engine:'selfguard-seclang-v1',bundleId:bundle?.id||'',bundleSha256:sha256,threshold,site:runtimeSite(site),files,...(!bundle?{builtin:true}:{})};
 const raw=Buffer.from(JSON.stringify(payload));if(raw.length>2250000)throw new BadRequestException('规则签名载荷超过限制');
 return {payload:raw.toString('base64'),signature:sign(null,raw,signingKey()).toString('base64')};
}
export function validateStoredWafEnvelope(envelope:any){
 try{if(!envelope||typeof envelope.payload!=='string'||typeof envelope.signature!=='string')throw Error();const raw=Buffer.from(envelope.payload,'base64'),signature=Buffer.from(envelope.signature,'base64');if(raw.toString('base64')!==envelope.payload||!verify(null,raw,createPublicKey(signingKey()),signature))throw Error();const value=JSON.parse(raw.toString('utf8'));if(value.schemaVersion!==1||value.engine!=='selfguard-seclang-v1')throw Error();return value;}catch{throw new ServiceUnavailableException('已有 WAF 发布签名无法核验，请恢复原签名密钥并检查发布记录');}
}

export async function persistWafDeployment(tx:any,site:any,bundle:{id:string;sha256:string;files:unknown}|null,threshold:number,actor:string,reason:string){
 const envelope=signWafRuntime(site,bundle,threshold),payload=JSON.parse(Buffer.from(envelope.payload,'base64').toString('utf8'));
 const row=await tx.wafRuleDeployment.create({data:{siteId:site.id,siteVersion:site.version,bundleId:bundle?.id||null,bundleSha256:payload.bundleSha256,mode:site.mode,threshold,envelope,previousId:site.ruleDeploymentId||null,actor,reason}});
 await tx.site.update({where:{id:site.id},data:{ruleDeploymentId:row.id}});
 await tx.audit.create({data:{actor,action:'SIGNED_RULE_POLICY',resource:'sites',resourceId:site.id,detail:{deploymentId:row.id,bundleId:row.bundleId,bundleSha256:row.bundleSha256,siteVersion:site.version,mode:site.mode,threshold,reason,previousId:row.previousId}}});
 return row;
}

export async function rebindSiteRuleDeployment(tx:any,site:any,actor:string){
 if(!site.ruleDeploymentId)return site;
 const previous=await tx.wafRuleDeployment.findUniqueOrThrow({where:{id:site.ruleDeploymentId}}),payload=validateStoredWafEnvelope(previous.envelope);
 if(previous.siteId!==site.id||payload.site.id!==site.id)throw new ServiceUnavailableException('站点与已有规则发布不一致');
 const bundle=payload.builtin?null:{id:payload.bundleId,sha256:payload.bundleSha256,files:payload.files};
 const next=await persistWafDeployment(tx,site,bundle,previous.threshold,actor,'站点配置更新，重新绑定并签名当前规则版本');
 return {...site,ruleDeploymentId:next.id};
}
