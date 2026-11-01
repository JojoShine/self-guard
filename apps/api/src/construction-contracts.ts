import {BadRequestException} from '@nestjs/common';
import {createPublicKey,verify} from 'node:crypto';
import {z} from 'zod';
import {parse} from './validation';

// Same signed bytes as the existing Agent upgrade protocol. Installation metadata
// belongs to the release record and cannot change the signed executable identity.
export const artifactManifestInput=z.object({
 version:z.string().regex(/^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?$/),
 sequence:z.number().int().positive().safe(),sha256:z.string().regex(/^[a-f0-9]{64}$/),
 size:z.number().int().min(1).max(64<<20),os:z.literal('linux'),
 architecture:z.enum(['amd64','arm64']),expiresAt:z.string().datetime(),
}).strict();
export const signedArtifactInput=z.object({manifestBytes:z.string().min(1).max(90000),signature:z.string().max(100)}).strict();
const packageManifestInput=artifactManifestInput.omit({sequence:true}).extend({kind:z.literal('selfguard-agent-package-v1'),format:z.enum(['tar.gz','deb','rpm']),executableSha256:z.string().regex(/^[a-f0-9]{64}$/)}).strict();
function verifySignedManifest<T>(envelope:z.infer<typeof signedArtifactInput>,root:string,schema:z.ZodType<T>,now:Date):T{
 try{
  const key=Buffer.from(root,'base64'),raw=Buffer.from(envelope.manifestBytes,'base64'),sig=Buffer.from(envelope.signature,'base64');
  if(key.length!==32||key.toString('base64')!==root||raw.length>65536||raw.toString('base64')!==envelope.manifestBytes||sig.length!==64||sig.toString('base64')!==envelope.signature)throw Error();
  const publicKey=createPublicKey({format:'der',type:'spki',key:Buffer.concat([Buffer.from('302a300506032b6570032100','hex'),key])});
  if(!verify(null,raw,publicKey,sig))throw Error();
  const manifest=schema.parse(JSON.parse(raw.toString('utf8')));
  if(Date.parse((manifest as any).expiresAt)<=now.getTime())throw Error();
  return manifest;
 }catch{throw new BadRequestException('制品清单、签名或有效期无效');}
}
export function verifyArtifactManifest(envelope:z.infer<typeof signedArtifactInput>,root:string,now=new Date()){
 return verifySignedManifest(envelope,root,artifactManifestInput,now);
}
export function verifyPackageManifest(envelope:z.infer<typeof signedArtifactInput>,root:string,release:{version:string;sha256:string;architecture:string},now=new Date()){
 const manifest=verifySignedManifest(envelope,root,packageManifestInput,now);
 if(manifest.version!==release.version||manifest.architecture!==release.architecture||manifest.executableSha256!==release.sha256)throw new BadRequestException('安装包与发行制品不一致');
 return manifest;
}
const values=z.array(z.string().trim().min(1).max(200)).min(1).max(1000);
const group=z.object({assetIds:values.optional(),businessIds:values.optional(),tags:values.optional(),types:z.array(z.enum(['HOST','SERVICE'])).min(1).max(2).optional()}).strict()
 .refine(v=>Object.values(v).some(x=>x&&x.length>0),'范围组必须至少包含一个条件');
const exclusion=z.object({...group.def.shape,expiresAt:z.string().datetime().optional()}).strict()
 .refine(v=>['assetIds','businessIds','tags','types'].some(k=>(v as any)[k]?.length),'排除组必须至少包含一个条件');
export const scanScopeInput=z.object({
 allAuthorized:z.boolean().default(false),include:z.array(group).max(100).default([]),exclude:z.array(exclusion).max(100).default([]),
 inventoryMaxAgeHours:z.number().int().min(1).max(168).default(24),
}).strict().refine(v=>v.allAuthorized?v.include.length===0:v.include.length>0,'必须选择明确范围或显式全部授权对象，二者不能混用');
export type ScanScope=z.infer<typeof scanScopeInput>;
export type ScopeTarget={id:string;businessId:string|null;tags:string[];type:'HOST'|'SERVICE'|string;archivedAt:Date|null;inventoryAt:Date|null};
function matches(g:z.infer<typeof group>,a:ScopeTarget){
 return (!g.assetIds||g.assetIds.includes(a.id))&&(!g.businessIds||!!a.businessId&&g.businessIds.includes(a.businessId))&&(!g.tags||g.tags.some(t=>a.tags.includes(t)))&&(!g.types||g.types.includes(a.type as 'HOST'|'SERVICE'));
}
export function resolveScanScope(input:ScanScope,assets:ScopeTarget[],authorized:ReadonlySet<string>,now=new Date(),requiresInventory=true){
 const scope=parse(scanScopeInput,input),selected:ScopeTarget[]=[],skipped:Array<{id:string;reason:string}>=[];
 for(const a of assets){
  if(!authorized.has(a.id)||!scope.allAuthorized&&!scope.include.some(g=>matches(g,a)))continue;
  let reason='';
  if(a.archivedAt)reason='ARCHIVED';
  else if(scope.exclude.some(g=>(!g.expiresAt||Date.parse(g.expiresAt)>now.getTime())&&matches(g,a)))reason='EXCLUDED';
  else if(requiresInventory){
   if(!a.inventoryAt)reason='MISSING_INVENTORY';
   else if(!Number.isFinite(a.inventoryAt.getTime())||a.inventoryAt>now)reason='INVALID_INVENTORY_TIME';
   else if(now.getTime()-a.inventoryAt.getTime()>scope.inventoryMaxAgeHours*3600000)reason='STALE_INVENTORY';
  }
  if(reason)skipped.push({id:a.id,reason});else selected.push(a);
 }
 return {selected,skipped,checkedAt:now.toISOString()};
}
export const scanOutcomeInput=z.enum(['CONFIRMED','POTENTIAL','NOT_FOUND','NOT_APPLICABLE','SKIPPED','INCONCLUSIVE']);
export function coverageSummary(results:z.infer<typeof scanOutcomeInput>[]){
 const count=(outcome:string)=>results.filter(x=>x===outcome).length;
 return {total:results.length,executed:count('CONFIRMED')+count('POTENTIAL')+count('NOT_FOUND'),confirmed:count('CONFIRMED'),potential:count('POTENTIAL'),notFound:count('NOT_FOUND'),notApplicable:count('NOT_APPLICABLE'),skipped:count('SKIPPED'),inconclusive:count('INCONCLUSIVE')};
}

// New component/scan lists follow the platform's 15-row UI contract.
export const componentPageInput=z.object({
 page:z.coerce.number().int().min(1).max(100000).default(1),
 pageSize:z.coerce.number().int().min(1).max(100).default(15),
 q:z.string().trim().max(500).default(''),
});
