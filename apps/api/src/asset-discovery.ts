import {createHash} from 'node:crypto';import {z} from 'zod';
import {Body,Controller,Get,Inject,Param,Patch,Post,Query,Req,UseGuards,ConflictException,NotFoundException,BadRequestException} from '@nestjs/common';import {Prisma} from '@prisma/client';
import {AuthGuard,allow} from './auth';import {Db} from './db';import {assetScope,assertGlobal,assertScope,assertEvidence} from './scope';import {parse,pageInput,text} from './validation';import {instanceInput,assertInstanceScope,assertInstanceBusiness,assertDatabaseRuleEngine} from './database-instances';import {SecurityRequest,SecurityUser} from './database-contract';
import {canonicalDiscoveryAddress,usableDiscoveryAddress,localDiscoveryAddresses} from './asset-discovery-address';
const endpoint=z.object({address:z.string().max(100),port:z.number().int().min(1).max(65535),protocol:z.enum(['tcp','tcp6','udp','udp6'])});
type Endpoint=z.infer<typeof endpoint>&{basis:'LISTEN'|'ESTABLISHED'};
export const discoveryPolicyInput=z.object({enabled:z.boolean().default(true),minimumObservations:z.number().int().min(1).max(10000).default(1),activeWithinHours:z.number().int().min(1).max(8760).default(168),excludedAddresses:z.array(z.union([z.ipv4(),z.ipv6()])).max(500).default([]),excludedPorts:z.array(z.number().int().min(1).max(65535)).max(500).default([])}).strict();
export function discoveredEndpoints(inventory:Record<string,unknown>,hostIp:string|null):Endpoint[]{
 const local=localDiscoveryAddresses(inventory,hostIp),out=new Map<string,Endpoint>();const rows=inventory.connections;if(!Array.isArray(rows))return [];
 for(const raw of rows.slice(0,2000)){const parsed=endpoint.safeParse(raw);if(!parsed.success)continue;const row=parsed.data,address=canonicalDiscoveryAddress(row.address);if(!address||!usableDiscoveryAddress(address)||local.has(address))continue;
 const protocol=row.protocol==='tcp6'?'tcp':row.protocol==='udp6'?'udp':row.protocol;const key=JSON.stringify([address,row.port,protocol]);if(!out.has(key))out.set(key,{...row,address,protocol,basis:'ESTABLISHED'});if(out.size>=500)break;}return [...out.values()];
}
async function managedAddresses(db:Pick<Prisma.TransactionClient,'$queryRaw'|'setting'>){
 const rows=await db.$queryRaw<Array<{ip:string|null;ports:Prisma.JsonValue}>>`SELECT ip, inventory->'ports' AS ports FROM "Asset"`;
 const addresses=new Set<string>();for(const row of rows)for(const address of localDiscoveryAddresses({ports:row.ports},row.ip))addresses.add(address);
 const platform=z.object({server:z.string().url(),verifiedAt:z.string()}).safeParse((await db.setting.findUnique({where:{key:'agent-platform:connection'}}))?.value);if(platform.success){const hostname=new URL(platform.data.server).hostname.replace(/^\[|\]$/g,''),address=canonicalDiscoveryAddress(hostname);if(address)addresses.add(address)}return addresses;
}
export async function recordCandidates(tx:Prisma.TransactionClient,asset:{id:string;ip:string|null},inventory:Record<string,unknown>){
 const policy=discoveryPolicyInput.parse((await tx.setting.findUnique({where:{key:'asset-discovery-policy'}}))?.value||{});if(!policy.enabled)return;
 const known=await managedAddresses(tx),excluded=new Set(policy.excludedAddresses.map(canonicalDiscoveryAddress));
 const handled=await tx.assetCandidate.findMany({where:{OR:[{status:'CLAIMED'},{sourceAssetId:asset.id,status:'DISMISSED'}]},select:{address:true}});for(const row of handled){const address=canonicalDiscoveryAddress(row.address);if(address)known.add(address)}
 const reportKey=createHash('sha256').update(JSON.stringify(inventory)).digest('hex');// Legacy public observations stay in history but must not consume the private-peer budget.
 const previousAddresses=await tx.assetCandidate.findMany({where:{sourceAssetId:asset.id},select:{address:true}});let capacity=5000-previousAddresses.filter(row=>usableDiscoveryAddress(row.address)).length;
 for(const row of discoveredEndpoints(inventory,asset.ip)){if(known.has(row.address)||excluded.has(row.address)||policy.excludedPorts.includes(row.port))continue;
 const key=createHash('sha256').update(JSON.stringify([asset.id,row.address,row.port,row.protocol])).digest('hex');const previous=await tx.assetCandidate.findUnique({where:{key}});if(previous?.lastReportKey===reportKey)continue;if(!previous&&capacity--<=0)continue;
 await tx.assetCandidate.upsert({where:{key},create:{key,sourceAssetId:asset.id,...row,lastReportKey:reportKey},update:{lastSeen:new Date(),observations:{increment:1},lastReportKey:reportKey,basis:row.basis}});}
}
async function candidateGroup(tx:Prisma.TransactionClient,user:SecurityUser,id:string){
 const initial=await tx.assetCandidate.findUnique({where:{id}});if(!initial)throw new NotFoundException();await assertScope(tx,user,'assets',initial.sourceAssetId);
 const address=canonicalDiscoveryAddress(initial.address);if(!address||!usableDiscoveryAddress(address))throw new ConflictException('此地址不是可自动认领的内网主机 IP，公网及特殊地址不参与自动发现');
 // Acquire the IP lock before any row lock: separate port observations may be claimed concurrently.
 await tx.$queryRaw`SELECT pg_advisory_xact_lock(hashtext(${'asset-candidate-ip:'+address}))::text`;
 await tx.$queryRaw`SELECT id FROM "AssetCandidate" WHERE id=${id} FOR UPDATE`;
 const row=await tx.assetCandidate.findUniqueOrThrow({where:{id}}),source=await tx.asset.findUniqueOrThrow({where:{id:row.sourceAssetId}});
 if(source.archivedAt||row.basis==='LISTEN'||localDiscoveryAddresses(source.inventory,source.ip).has(address))throw new ConflictException('本机监听或本机地址不能重复认领');
 const sources=await tx.asset.findMany({where:{...assetScope(user),archivedAt:null},select:{id:true}}),observations=await tx.assetCandidate.findMany({where:{sourceAssetId:{in:sources.map(s=>s.id)}}});
 return {row,address,ids:observations.filter(r=>canonicalDiscoveryAddress(r.address)===address).map(r=>r.id)};
}
@Controller('asset-candidates') @UseGuards(AuthGuard)
export class AssetDiscoveryController{
 constructor(@Inject(Db)private db:Db){}
 @Get('policy')async policy(@Req()req:SecurityRequest){assertGlobal(req.user);assertEvidence(req.user);return discoveryPolicyInput.parse((await this.db.setting.findUnique({where:{key:'asset-discovery-policy'}}))?.value||{});}
 @Patch('policy')async configure(@Req()req:SecurityRequest,@Body()body:unknown){allow(req,['ADMIN','ANALYST']);assertGlobal(req.user);const value=parse(discoveryPolicyInput,body);return this.db.$transaction(async tx=>{await tx.setting.upsert({where:{key:'asset-discovery-policy'},create:{key:'asset-discovery-policy',value},update:{value}});await tx.audit.create({data:{actor:req.user.email,action:'DISCOVERY_POLICY',resource:'settings',detail:value}});return value;});}
 @Get()async list(@Req()req:SecurityRequest,@Query()query:unknown){
 assertEvidence(req.user);const v=parse(pageInput.extend({status:z.enum(['PENDING','CLAIMED','DISMISSED']).optional()}),query),policy=discoveryPolicyInput.parse((await this.db.setting.findUnique({where:{key:'asset-discovery-policy'}}))?.value||{});
 const sources=await this.db.asset.findMany({where:{...assetScope(req.user),archivedAt:null},select:{id:true,hostname:true,ip:true,inventory:true}}),known=await managedAddresses(this.db),excluded=new Set(policy.excludedAddresses.map(canonicalDiscoveryAddress));
 const claimed=await this.db.assetCandidate.findMany({where:{OR:[{status:'CLAIMED'},{status:'DISMISSED',sourceAssetId:{in:sources.map(source=>source.id)}}]},select:{address:true}});for(const r of claimed){const address=canonicalDiscoveryAddress(r.address);if(address)known.add(address)}
 const rows=await this.db.assetCandidate.findMany({where:{sourceAssetId:{in:sources.map(a=>a.id)},...(v.status?{status:v.status}:{})},orderBy:[{lastSeen:'desc'},{id:'asc'}]});
 const groups=new Map<string,typeof rows>();const sourceById=new Map(sources.map(source=>[source.id,source]));
 for(const row of rows){const address=canonicalDiscoveryAddress(row.address),source=sourceById.get(row.sourceAssetId);if(!address||!source||v.q&&!address.includes(v.q.toLowerCase()))continue;
 if(row.status==='PENDING'&&(!usableDiscoveryAddress(address)||row.basis==='LISTEN'||known.has(address)||localDiscoveryAddresses(source.inventory,source.ip).has(address)||excluded.has(address)||policy.excludedPorts.includes(row.port)||row.lastSeen.getTime()<Date.now()-policy.activeWithinHours*3600000))continue;
 const group=groups.get(address);if(group)group.push({...row,address});else groups.set(address,[{...row,address}]);}
 const items=[...groups.values()].map(rows=>{const row=rows[0],endpoints=[...new Map(rows.map(r=>[r.port+'/'+r.protocol,{port:r.port,protocol:r.protocol}])).values()],sourceHostnames=[...new Set(rows.map(r=>sourceById.get(r.sourceAssetId)!.hostname))],counts=new Map<string,number>();for(const r of rows)counts.set(r.sourceAssetId,Math.max(counts.get(r.sourceAssetId)||0,r.observations));return {...row,firstSeen:rows.reduce((first,r)=>r.firstSeen<first?r.firstSeen:first,row.firstSeen),observations:[...counts.values()].reduce((a,b)=>a+b,0),endpoints,sourceHostnames,sourceHostname:sourceHostnames.join('、'),confidence:'按 IP 汇总连接观察，端口仅作为证据，类型与归属待确认'};}).filter(row=>row.status!=='PENDING'||row.observations>=policy.minimumObservations);
 return {items:items.slice((v.page-1)*v.pageSize,v.page*v.pageSize),total:items.length,canManage:['ADMIN','ANALYST'].includes(req.user.role)};
 }
 @Post(':id/claim')async claim(@Req()req:SecurityRequest,@Param('id')id:string,@Body()body:unknown){allow(req,['ADMIN','ANALYST']);assertEvidence(req.user);const v=parse(z.discriminatedUnion('kind',[z.object({kind:z.literal('DATABASE'),instance:instanceInput}).strict(),z.object({kind:z.literal('EXISTING_DATABASE'),instanceId:z.string().uuid()}).strict(),z.object({kind:z.literal('HOST'),hostname:text,owner:text,business:text.optional()}).strict(),z.object({kind:z.literal('EXISTING_HOST'),assetId:z.string().uuid()}).strict()]),body);
 return this.db.$transaction(async tx=>{const{row,address,ids}=await candidateGroup(tx,req.user,id);if(row.status!=='PENDING')throw new ConflictException('候选已处理');
 const claimed=await tx.assetCandidate.findMany({where:{status:'CLAIMED'},select:{address:true}});if(claimed.some(r=>canonicalDiscoveryAddress(r.address)===address))throw new ConflictException('此 IP 已认领，无需按端口重复认领');
 if(v.kind==='HOST'&&(await managedAddresses(tx)).has(address))throw new ConflictException('此 IP 已登记，请在资产清单查询或恢复，不能重复新建');let targetAssetId:string|undefined,instanceId:string|undefined;
 if(v.kind==='DATABASE'){assertInstanceBusiness(req.user,v.instance.business);for(const source of v.instance.auditSources){if(!v.instance.hostIds.includes(source.assetId))throw new BadRequestException('审计来源必须关联授权采集主机');assertDatabaseRuleEngine(v.instance.engine,{service:source.format});}for(const host of v.instance.hostIds)await assertScope(tx,req.user,'assets',host);instanceId=(await tx.databaseInstance.create({data:v.instance})).id;if(v.instance.business)await tx.businessGroup.upsert({where:{name:v.instance.business},create:{name:v.instance.business},update:{}});}
 else if(v.kind==='EXISTING_DATABASE'){const instance=await assertInstanceScope(tx,req.user,v.instanceId);if(instance.archivedAt)throw new ConflictException('实例已归档');instanceId=instance.id;}
 else{if(v.kind==='EXISTING_HOST'){await assertScope(tx,req.user,'assets',v.assetId);const asset=await tx.asset.findUniqueOrThrow({where:{id:v.assetId}});if(asset.archivedAt)throw new ConflictException('资产已归档');if(canonicalDiscoveryAddress(asset.ip||'')!==address)throw new BadRequestException('所选资产 IP 与候选 IP 不一致');targetAssetId=asset.id;}else{assertInstanceBusiness(req.user,v.business);targetAssetId=(await tx.asset.create({data:{hostname:v.hostname,os:'unknown',ip:address,owner:v.owner,business:v.business,inventory:{discoveredEndpoint:{...row}}}})).id;}}
 await tx.assetCandidate.updateMany({where:{id:{in:ids},status:'PENDING'},data:{status:'CLAIMED',targetAssetId,instanceId}});await tx.audit.create({data:{actor:req.user.email,action:'CLAIM',resource:'asset-candidates',resourceId:id,detail:{targetAssetId,instanceId,kind:v.kind}}});return{targetAssetId,instanceId};});}
 @Post(':id/dismiss')async dismiss(@Req()req:SecurityRequest,@Param('id')id:string,@Body()body:unknown){return this.transition(req,id,body,'PENDING','DISMISSED');}
 @Post(':id/restore')async restore(@Req()req:SecurityRequest,@Param('id')id:string,@Body()body:unknown){return this.transition(req,id,body,'DISMISSED','PENDING');}
 private async transition(req:SecurityRequest,id:string,body:unknown,from:string,status:string){allow(req,['ADMIN','ANALYST']);assertEvidence(req.user);const v=parse(z.object({reason:text}).strict(),body);return this.db.$transaction(async tx=>{const{row,address,ids}=await candidateGroup(tx,req.user,id);if(row.status!==from)throw new ConflictException('候选状态已变化');if(status==='PENDING'&&(await managedAddresses(tx)).has(address))throw new ConflictException('此 IP 已登记，无需恢复认领');const changed=await tx.assetCandidate.updateMany({where:{id:{in:ids},status:from},data:{status,reason:v.reason}});if(!changed.count)throw new ConflictException('候选状态已变化');await tx.audit.create({data:{actor:req.user.email,action:status==='PENDING'?'RESTORE':'DISMISS',resource:'asset-candidates',resourceId:id,detail:{...v,address,observationIds:ids}}});return{ok:true};});}
}
