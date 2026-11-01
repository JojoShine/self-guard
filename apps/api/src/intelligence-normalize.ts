import {createHash} from 'node:crypto';import {z} from 'zod';import {canonicalPackageName} from './package-identity';
export type IntelligenceProvider='OSV'|'ALPINE'|'NVD'|'CISA_KEV'|'DEBIAN';
export type IntelligenceRecord={externalId:string;aliases:string[];summary:string;details:string;severity:string|null;scores:any[];purpose:'PACKAGE'|'CANDIDATE'|'PRIORITY'|'METADATA';affected:any[];packages:string[];references:any[];modifiedAt:string|null;withdrawnAt:string|null;metadata:Record<string,unknown>;rawSha256:string};
export type NormalizedIntelligence={version:string;records:IntelligenceRecord[];coverage:string};
const text=z.string().trim().min(1).max(100000),identifier=z.string().trim().min(1).max(500),cve=z.string().regex(/^CVE-\d{4}-\d{4,}$/);
function array(value:unknown,maximum=100000):any[]{return z.array(z.unknown()).max(maximum).parse(value) as any[]}
function object(value:unknown):Record<string,any>{return z.record(z.string(),z.unknown()).parse(value)}
function aliases(values:unknown[]){return [...new Set(values.map(value=>identifier.parse(value)))].sort()}
function rating(value:unknown){const level=typeof value==='string'?value.toUpperCase():'';return ['CRITICAL','HIGH','MEDIUM','LOW','INFO'].includes(level)?level:level==='MODERATE'?'MEDIUM':null}
function date(value:unknown):string|null {if(value==null)return null;const input=z.string().max(100).parse(value),normalized=/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?$/.test(input)?input+'Z':input;if(!Number.isFinite(Date.parse(normalized)))throw Error('无效的来源时间');return new Date(normalized).toISOString()}
function references(value:unknown,maximum=1000){return value==null?[]:array(value,maximum).map(item=>object(item))}
function record(id:string,raw:unknown,maximum=2*1024*1024):IntelligenceRecord {
 const bytes=JSON.stringify(raw);if(Buffer.byteLength(bytes)>maximum)throw Error('单条情报超过当前来源预算');
 return {externalId:identifier.parse(id),aliases:aliases([id]),summary:id,details:'',severity:null,scores:[],purpose:'METADATA',affected:[],packages:[],references:[],modifiedAt:null,withdrawnAt:null,metadata:{},rawSha256:createHash('sha256').update(bytes).digest('hex')};
}
function scheme(ecosystem:string){if(/^(Debian|Ubuntu)(:|$)/.test(ecosystem))return 'DEBIAN';if(/^Alpine(:|$)/.test(ecosystem))return 'APK';if(/^(Rocky Linux|AlmaLinux|Red Hat)(:|$)/.test(ecosystem))return 'RPM';return ({npm:'SEMVER',Go:'GO',PyPI:'PEP440',Maven:'MAVEN'} as Record<string,string>)[ecosystem]||'UNKNOWN'}
function osv(raw:unknown,ubuntuProfile=false):NormalizedIntelligence {
 const maximum=(ubuntuProfile?4:2)*1024*1024,linkLimit=ubuntuProfile?10000:1000;
 const input=object(raw),id=identifier.parse(input.id),result=record(id,raw,maximum);if(!input.modified)throw Error('OSV通告缺少修改时间');result.aliases=aliases([id,...array(input.aliases||[],100)]);result.summary=input.summary?text.parse(input.summary):id;result.details=input.details?text.parse(input.details):'';result.modifiedAt=date(input.modified);result.withdrawnAt=date(input.withdrawn);result.references=references(input.references,linkLimit);result.severity=rating(input.database_specific?.severity);
 const upstream=array(input.upstream||[],linkLimit).map(value=>identifier.parse(value)),related=array(input.related||[],linkLimit).map(value=>identifier.parse(value));
 if(/^UBUNTU-CVE-\d{4}-\d{4,}$/.test(id)&&upstream.includes(id.slice(7)))result.aliases=aliases([...result.aliases,id.slice(7)]);
 if(!result.severity)result.severity=rating(array(input.severity||[],100).find((metric:any)=>metric?.type==='Ubuntu')?.score);
 result.scores=array(input.severity||[],100).map(item=>{const metric=object(item),vector=z.string().max(2000).parse(metric.score);return {version:vector.match(/^CVSS:(\d\.\d)/)?.[1]||String(metric.type||'UNKNOWN'),vector,score:null,severity:null,source:'OSV:'+id,type:metric.type||'UNKNOWN'}});
 const withdrawnIdentityIssues:any[]=[];let unscopedAffectedCount=0;
 for(const item of array(input.affected||[],10000)){
  const affected=object(item);
  if(affected.package===undefined){
   const versions=array(affected.versions||[],100000).map(v=>identifier.parse(v)),ranges=array(affected.ranges||[],10000);
   result.affected.push({kind:'OSV_UNSCOPED',scheme:'UNKNOWN',versions,ranges,databaseSpecific:affected.database_specific||null,ecosystemSpecific:affected.ecosystem_specific||null});unscopedAffectedCount++;continue;
  }
  const pkg=object(affected.package),reportedEcosystem=identifier.parse(pkg.ecosystem),ecosystem=reportedEcosystem.replace(/^Ubuntu:(\d{2}\.\d{2}):LTS$/,'Ubuntu:$1'),reportedPackage=identifier.parse(pkg.name);let name:string,kind='OSV_PACKAGE';
  try{name=reportedPackage==='*'?'*':canonicalPackageName(ecosystem,reportedPackage);}catch(error){
   if(!result.withdrawnAt)throw error;
   // Withdrawn historical identities are retained as source facts, never
   // normalized into a current registry name or used by active matching.
   name=reportedPackage;kind='OSV_WITHDRAWN_PACKAGE';withdrawnIdentityIssues.push({ecosystem,reportedPackage,reason:error instanceof Error?error.message:'已撤回历史名称无法按现行规范归一化'});
  }
  const versions=array(affected.versions||[],100000).map(v=>identifier.parse(v)),ranges=array(affected.ranges||[],10000);
  result.affected.push({kind,ecosystem,reportedEcosystem,package:name,reportedPackage,...(typeof pkg.purl==='string'?{purl:z.string().max(4096).parse(pkg.purl)}:{}),scheme:kind==='OSV_PACKAGE'?scheme(ecosystem):'UNKNOWN',versions,ranges,databaseSpecific:affected.database_specific||null,ecosystemSpecific:affected.ecosystem_specific||null});result.packages.push(ecosystem+':'+name);
 }
 const vendorAdvisory=/^(?:USN|LSN)-/.test(id)&&(ubuntuProfile||result.affected.some(row=>String(row.ecosystem||'').startsWith('Ubuntu:')));
 result.purpose=vendorAdvisory?'METADATA':result.affected.some(row=>row.kind!=='OSV_UNSCOPED')?'PACKAGE':unscopedAffectedCount?'CANDIDATE':'METADATA';result.packages=[...new Set(result.packages)];result.metadata={databaseSpecific:input.database_specific||null,published:date(input.published),...(vendorAdvisory?{vendorAdvisory:true}:{}),...(upstream.length?{upstream}:{}),...(related.length?{related}:{}),...(withdrawnIdentityIssues.length?{withdrawnIdentityIssues}:{}),...(unscopedAffectedCount?{unscopedAffectedCount,scopeWarning:'上游未提供软件包身份；保留版本及代码范围，不能凭此确认已安装软件受影响'}:{})};
 return {version:result.modifiedAt||result.rawSha256,records:[result],coverage:'指定OSV通告的原始生态、版本与范围；实际匹配需对应生态比较器'};
}
function alpine(raw:unknown):NormalizedIntelligence {
 const input=object(raw),branch=z.string().regex(/^v\d+\.\d+$/).parse(input.distroversion),repo=identifier.parse(input.reponame),seen=new Set<string>(),byId=new Map<string,IntelligenceRecord>();
 for(const item of array(input.packages)){const pkg=object(object(item).pkg),name=identifier.parse(pkg.name);if(seen.has(name))throw Error('来源重复软件包，无法确认完整快照');seen.add(name);
  for(const [fixed,identities]of Object.entries(object(pkg.secfixes))){identifier.parse(fixed);for(const identity of array(identities,10000)){const id=identifier.parse(identity);let entry=byId.get(id);if(!entry){entry=record(id,{branch,repo,id});entry.summary=id+' · Alpine '+branch;entry.purpose='PACKAGE';entry.metadata={branch,repository:repo};byId.set(id,entry)}entry.affected.push({kind:'DISTRIBUTION_FIX',ecosystem:'Alpine:'+branch,distribution:'alpine',release:branch.slice(1),repository:repo,package:name,scheme:'APK',fixed});entry.packages.push('Alpine:'+branch+':'+name);}}
 }
 for(const entry of byId.values()){entry.packages=[...new Set(entry.packages)];entry.rawSha256=createHash('sha256').update(JSON.stringify(entry.affected)).digest('hex')}
 const digest=createHash('sha256').update(JSON.stringify(raw)).digest('hex');return {version:branch+'/'+repo+'@'+digest.slice(0,16),records:[...byId.values()],coverage:'指定Alpine分支和仓库的源包修复记录；需结合apk实际版本及origin匹配'};
}
function kev(raw:unknown):NormalizedIntelligence {
 const input=object(raw),entries=array(input.vulnerabilities),count=z.number().int().min(0).parse(input.count);if(count!==entries.length)throw Error('KEV目录数量不完整，保留上一份快照');date(input.dateReleased);
 const records=entries.map(item=>{const entry=object(item),id=cve.parse(entry.cveID),result=record(id,item);result.summary=text.parse(entry.vulnerabilityName);result.details=text.parse(entry.shortDescription);result.purpose='PRIORITY';result.metadata={knownExploited:true,vendor:entry.vendorProject,product:entry.product,dateAdded:date(entry.dateAdded),dueDate:date(entry.dueDate),requiredAction:text.parse(entry.requiredAction),ransomwareUse:entry.knownRansomwareCampaignUse||'Unknown',notes:entry.notes||'',weaknesses:entry.cwes||[]};return result});
 return {version:identifier.parse(input.catalogVersion),records,coverage:'在野利用优先级目录；不单独证明某项资产存在漏洞'};
}
function nvd(raw:unknown):NormalizedIntelligence {
 const input=object(raw),entries=array(input.vulnerabilities),total=z.number().int().min(0).parse(input.totalResults),start=z.number().int().min(0).parse(input.startIndex);if(start!==0||total!==entries.length)throw Error('NVD来源范围分页尚未完整，不能发布快照');
 const records=entries.map(item=>{const entry=object(object(item).cve),id=cve.parse(entry.id),result=record(id,entry),descriptions=array(entry.descriptions||[],100);result.summary=text.parse(descriptions.find(d=>d?.lang==='zh')?.value||descriptions.find(d=>d?.lang==='en')?.value||id);result.details=result.summary;result.modifiedAt=date(entry.lastModified);result.withdrawnAt=entry.vulnStatus==='Rejected'?result.modifiedAt:null;result.references=references(entry.references);result.purpose='CANDIDATE';
  if(entry.configurations)result.affected=[{kind:'CPE_CONFIGURATION',configuration:array(entry.configurations,10000)}];
  for(const [kind,metrics]of Object.entries(object(entry.metrics||{}))){if(!kind.startsWith('cvssMetric'))continue;for(const item of array(metrics,100)){const metric=object(item),data=object(metric.cvssData),score=data.baseScore==null?null:z.number().min(0).max(10).parse(data.baseScore);result.scores.push({version:identifier.parse(data.version),vector:z.string().max(2000).parse(data.vectorString),score,severity:rating(data.baseSeverity??metric.baseSeverity),source:identifier.parse(metric.source),type:metric.type||'UNKNOWN'})}}
  const preferred=[...result.scores].sort((a,b)=>Number(b.version)-Number(a.version)||(b.type==='Primary'?1:0)-(a.type==='Primary'?1:0)||(b.score||0)-(a.score||0))[0];result.severity=preferred?.severity||null;result.metadata={status:entry.vulnStatus||'UNKNOWN',published:date(entry.published),weaknesses:entry.weaknesses||[],metrics:entry.metrics||{},severityConflict:new Set(result.scores.map(s=>s.severity).filter(Boolean)).size>1};return result;
 });
 return {version:date(input.timestamp)||'NVD-response',records,coverage:'指定NVD范围的描述、评分、弱点和完整CPE条件；CPE仅作为产品适用候选'};
}
export function normalizeIntelligence(provider:Exclude<IntelligenceProvider,'DEBIAN'>,raw:unknown,profile?:'UBUNTU_ARCHIVE'):NormalizedIntelligence {
 const result=provider==='OSV'?osv(raw,profile==='UBUNTU_ARCHIVE'):({ALPINE:alpine,NVD:nvd,CISA_KEV:kev}[provider])(raw);const seen=new Set<string>();for(const record of result.records){if(seen.has(record.externalId))throw Error('来源包含重复情报标识，无法发布完整快照');seen.add(record.externalId)}return result;
}
