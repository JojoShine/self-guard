import {networkResult} from './scan-network-contracts';
import {NotFoundException} from '@nestjs/common';
import {Db} from './db';import {assertScope,resourceWhere,restricted,assetScope,evidenceAllowed} from './scope';
export function evidenceObject(value:unknown):Record<string,any>{
 let parsed=value;for(let i=0;i<2&&typeof parsed==='string';i++){if(parsed.length>100000)return {};try{parsed=JSON.parse(parsed)}catch{return {}}}
 return parsed&&typeof parsed==='object'&&!Array.isArray(parsed)?parsed as Record<string,any>:{};
}
export async function inventoryFindingEvidence(db:Db,finding:any):Promise<unknown>{
 const saved=evidenceObject(finding.evidence);
 if(finding.source!=='vulnerability'||!finding.externalId?.startsWith('inventory:')||saved.proofType!=='INVENTORY_VERSION_MATCH'||!finding.assetId||typeof saved.targetId!=='string'||typeof saved.runId!=='string'||!saved.component||typeof saved.component!=='object'||Array.isArray(saved.component))return finding.evidence;
 const identity=finding.externalId.slice('inventory:'.length,finding.externalId.lastIndexOf(':'));
 const rows=await db.$queryRaw<Array<{evidence:any;hostname:string;inventoryAt:Date|null;inventorySha256:string;ports:any;portCollection:any}>>`
 SELECT hit->'evidence' AS evidence,t.hostname,t."inventoryAt",t."inventorySha256",t.inventory->'ports' AS ports,t.inventory->'portCollection' AS "portCollection"
 FROM "ScanTarget" t CROSS JOIN LATERAL jsonb_array_elements(CASE WHEN jsonb_typeof(t.result->'findings')='array' THEN t.result->'findings' ELSE '[]'::jsonb END) hit
 WHERE t.id=${saved.targetId} AND t."runId"=${saved.runId} AND t."assetId"=${finding.assetId}
 AND t.result->'findingIds' ? ${finding.id} AND hit->>'identity'=${identity}
 AND hit->'evidence'->'component'=${JSON.stringify(saved.component)}::jsonb LIMIT 1`;
 const row=rows[0];if(!row)return finding.evidence;
 const ports=Array.isArray(row.ports)?row.ports:[],valid=ports.filter((port:any)=>port&&['tcp','tcp6','udp','udp6'].includes(port.protocol)&&typeof port.address==='string'&&port.address.length<=500&&Number.isInteger(port.port)&&port.port>=1&&port.port<=65535&&port.state==='LISTEN');
 return {...saved,...row.evidence,hostNetworkSnapshot:{assetId:finding.assetId,hostname:row.hostname,inventoryAt:row.inventoryAt,inventorySha256:row.inventorySha256,ports:valid.slice(0,500),totalPorts:ports.length,complete:row.portCollection?.complete===true&&valid.length===ports.length,omitted:ports.length-Math.min(valid.length,500),reason:(typeof row.portCollection?.reason==='string'?row.portCollection.reason.slice(0,1000):undefined)||(!Array.isArray(row.ports)?'当时没有保存监听清单':undefined),meaning:'本次扫描冻结的同主机监听环境；不证明该漏洞通过这些端口暴露，也不证明外部可达、实际连接或已发生利用。'}};
}
export async function activeFindingEvidence(db:Db,finding:any):Promise<unknown>{
 const saved=evidenceObject(finding.evidence);
 if(finding.source!=='active-scan'||!finding.externalId?.startsWith('active:')||!['ACTIVE_HTTP_CHECK','ACTIVE_NETWORK_CHECK'].includes(saved.proofType)||!finding.assetId||typeof saved.probeId!=='string'||typeof saved.targetId!=='string'||typeof saved.runId!=='string')return finding.evidence;
 const rows=await db.$queryRaw<Array<{execution:any;endpoint:any;check:any;templatePin:any;endpointPin:any;templateSource:any;templateName:string;endpointName:string;remediation:string;hostname:string}>>`
 SELECT p.result AS execution,p."templateName",p."endpointName",p.remediation,t.hostname,
 t.inventory->'active'->'endpoints'->p."endpointIndex" AS endpoint,
 t.inventory->'active'->'checks'->p."checkIndex" AS check,
 t.inventory->'activeSources'->'templates'->p."checkIndex" AS "templatePin",
 t.inventory->'templateSources'->p."checkIndex" AS "templateSource",
 t.inventory->'activeSources'->'endpoints'->p."endpointIndex" AS "endpointPin"
 FROM "ScanProbe" p JOIN "ScanTarget" t ON t.id=p."targetId"
 WHERE p.id=${saved.probeId} AND p."targetId"=${saved.targetId} AND t."runId"=${saved.runId}
 AND t."assetId"=${finding.assetId} AND p."findingId"=${finding.id} AND p.status='CONFIRMED'
 AND p.result->>'outcome'='CONFIRMED'
 AND ${finding.externalId}='active:'||p."endpointId"||':'||p."templateId" LIMIT 1`;
 const row=rows[0];if(!row)return finding.evidence;
 if(row.execution?.checkType==='NETWORK'){
  const {engineVersion,checkType,...execution}=row.execution,parsed=networkResult.safeParse(execution);if(saved.proofType!=='ACTIVE_NETWORK_CHECK'||!parsed.success||parsed.data.outcome!=='CONFIRMED'||row.check?.kind!=='NETWORK'||parsed.data.evidence.ruleId!==row.check.rule.id||parsed.data.evidence.checkKind!==row.check.rule.kind||parsed.data.evidence.hostname!==row.endpoint?.hostname||parsed.data.evidence.port!==row.endpoint?.port||parsed.data.evidence.protocol!==row.endpoint?.protocol)return finding.evidence;
  return {...saved,description:parsed.data.evidence.description,templateName:row.templateName,endpointName:row.endpointName,remediation:row.remediation,endpoint:row.endpoint,check:row.check,networkProof:parsed.data.evidence,outcome:parsed.data.outcome,engineVersion,templateSource:row.templateSource,templatePin:row.templatePin,endpointPin:row.endpointPin,meaning:'实际只读服务观测满足固定模板条件。证书和服务特征来自本次检查；扫描连接方向为扫描节点到受检服务，不是攻击者流量，不证明成功利用或完整攻击链。'};
 }
 if(saved.proofType!=='ACTIVE_HTTP_CHECK')return finding.evidence;
 return {...saved,description:row.execution.evidence.description,templateName:row.templateName,endpointName:row.endpointName,remediation:row.remediation,endpoint:row.endpoint,check:row.check,httpProof:row.execution.evidence,outcome:row.execution.outcome,engineVersion:row.execution.engineVersion,templateSource:row.templateSource,templatePin:row.templatePin,endpointPin:row.endpointPin,meaning:'真实只读HTTP响应满足固定模板条件；扫描连接不代表攻击者流量，也不能据此认定成功利用或完整攻击链。'};
}
const assetFields={id:true,hostname:true,ip:true,os:true,business:true,lastSeen:true} as const;
const signalFields={id:true,externalId:true,title:true,kind:true,severity:true,status:true,source:true,evidence:true,assetId:true,createdAt:true,updatedAt:true} as const;
function value(input:unknown){return typeof input==='string'||typeof input==='number'?String(input).slice(0,500):undefined;}
export function networkEvidence(signals:any[],sites:any[],events:any[]){
 const relations:any[]=[];const seen=new Set<string>();
 function add(relation:any){const key=JSON.stringify([relation.kind,relation.from,relation.to,relation.findingId,relation.eventId]);if(!seen.has(key)){seen.add(key);relations.push(relation)}}
 for(const signal of signals){const evidence=evidenceObject(signal.evidence),site=sites.find(s=>s.id===evidence.siteId);const from=value(evidence.sourceIp??evidence.srcIp),to=value(evidence.destinationIp??evidence.dstIp);
  if(from&&to)add({kind:'REPORTED_CONNECTION',from,to,port:value(evidence.destinationPort??evidence.dstPort),protocol:value(evidence.protocol),findingId:signal.id,basis:'该发现的实际证据字段；不代表已还原完整攻击路径'});
  const scanProof=evidence.proofType==='ACTIVE_NETWORK_CHECK'?evidence.networkProof:evidence.proofType==='ACTIVE_HTTP_CHECK'?evidence.httpProof:undefined;
  if(signal.source==='active-scan'&&signal.evidence&&typeof signal.evidence==='object'&&!Array.isArray(signal.evidence)&&Array.isArray(scanProof?.connections))for(const connection of scanProof.connections.slice(0,4)){
   const source=value(connection.source),destination=value(connection.destination);if(source&&destination&&connection.transport==='TCP')add({kind:'SCANNER_CONNECTION',from:source,to:destination,protocol:'TCP',findingId:signal.id,basis:'本次扫描进程实际建立的连接；方向为扫描节点到受检服务，不是攻击者流量，不证明后续业务调用或完整攻击链'});
  }
  const inspection=evidenceObject(evidence.inspection),recordedHost=value(inspection.siteHostname),upstream=value(inspection.configuredUpstreamOrigin);
  if((recordedHost||site)&&value(evidence.remoteIp))add({kind:'REPORTED_REQUEST',from:value(evidence.remoteIp),to:recordedHost||site.hostname,method:value(evidence.method),route:value(evidence.path),findingId:signal.id,basis:recordedHost?'WAF记录中保存的来源地址及当时防护站点':'WAF记录引用的来源及站点；未保留历史域名，名称来自当前配置'});
  if(recordedHost&&upstream)add({kind:'CONFIGURED_ROUTING_SNAPSHOT',from:recordedHost,to:upstream,findingId:signal.id,basis:'记录保存的当时站点策略 v'+String(inspection.siteVersion??'未知')+'；'+(evidence.action==='BLOCK'?'本次已阻断，未转发至上游':'配置目标，不证明本次请求已经到达上游')});
 }
 for(const event of events){const data=evidenceObject(event.data),from=value(data.sourceIp??data.srcIp),to=value(data.destinationIp??data.dstIp);if(from&&to)add({kind:'REPORTED_CONNECTION',from,to,port:value(data.destinationPort??data.dstPort),protocol:value(data.protocol),eventId:event.id,at:event.occurredAt,basis:'该发现明确引用的原始安全事件'});}
 for(const site of sites){let upstream;try{const url=new URL(site.upstream);if(!['http:','https:'].includes(url.protocol))continue;upstream=url.origin}catch{continue}add({kind:'CONFIGURED_ROUTING',from:site.hostname,to:upstream,basis:'当前站点转发配置；不证明历史请求采用此配置或已经到达上游'});}
 return {relations,missing:['未提供完整会话追踪或跨主机关联证据时，不能确认后续横向移动、跨服务调用或完整攻击链。']};
}
export async function investigationContext(db:Db,user:any,resource:string,id:string,page=1,pageSize=15){
 if(!['findings','incidents'].includes(resource))throw new NotFoundException();await assertScope(db,user,resource,id);
 const record=resource==='findings'?await db.finding.findUniqueOrThrow({where:{id}}):await db.incident.findUniqueOrThrow({where:{id}});
 const where={AND:[resource==='findings'?{id}:{links:{some:{incidentId:id}}},await resourceWhere(db,user,'findings')]};
 const [signals,total]=await Promise.all([db.finding.findMany({where,select:signalFields,orderBy:[{updatedAt:'desc'},{id:'asc'}],skip:(page-1)*pageSize,take:pageSize}),db.finding.count({where})]);
 const assetIds=[...new Set([...signals.map(f=>f.assetId).filter(Boolean),...('assetIds' in record?record.assetIds:[])])].slice(0,100) as string[];
 const assets=await db.asset.findMany({where:{AND:[{id:{in:assetIds}},await resourceWhere(db,user,'assets')]},select:assetFields,orderBy:{hostname:'asc'}});
 const findings=evidenceAllowed(user)?await Promise.all(signals.map(async signal=>({...signal,evidence:signal.source==='active-scan'?await activeFindingEvidence(db,signal):await inventoryFindingEvidence(db,signal)}))):signals;
 const objects=signals.map(f=>evidenceObject(f.evidence));const siteIds=[...new Set(objects.map(e=>e.siteId).filter((v):v is string=>typeof v==='string'))].slice(0,100);
 const sites=restricted(user)?[]:await db.site.findMany({where:{id:{in:siteIds}},select:{id:true,name:true,hostname:true,upstream:true}});
 const eventIds=[...new Set(objects.flatMap(e=>Array.isArray(e.eventIds)?e.eventIds.filter((v:unknown)=>typeof v==='string'):[]))].slice(0,100) as string[];
 const allowedAssets=restricted(user)?await db.asset.findMany({where:assetScope(user),select:{id:true}}):undefined;
 const events=eventIds.length?await db.telemetryEvent.findMany({where:{id:{in:eventIds},expiresAt:{gt:new Date()},...(allowedAssets?{assetId:{in:allowedAssets.map(a=>a.id)}}:{})},select:{id:true,source:true,type:true,assetId:true,occurredAt:true,data:true},orderBy:[{occurredAt:'asc'},{id:'asc'}],take:100}):[];
 return {resource,id,page,pageSize,total,evidence:{description:'description' in record?record.description:undefined,assets,findings,events,network:networkEvidence(findings,sites,events),coverage:{findingPage:page,findingsOnPage:signals.length,totalFindings:total,referencedEventLimit:100,returnedEvents:events.length}}};
}
