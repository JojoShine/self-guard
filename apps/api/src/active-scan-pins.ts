import {instantiateProbeCheck} from './probe-source';
import {createHash} from 'node:crypto';
import {ConflictException} from '@nestjs/common';import {isDeepStrictEqual} from 'node:util';import {z} from 'zod';import type {Prisma} from '@prisma/client';
const pin=z.object({id:z.string().uuid(),version:z.number().int().positive(),approvalHash:z.string().regex(/^[a-f0-9]{64}$/)}).strict();
const pins=(maximum:number)=>z.array(pin).min(1).max(maximum).refine(rows=>new Set(rows.map(row=>row.id)).size===rows.length);
export const activeSourcePins=z.object({endpoints:pins(100),templates:pins(5000),requestLimit:z.number().int().min(1).max(10000).optional(),domainResolutionVersion:z.string().max(100).optional()}).strict();
type ApprovalTemplate={sourceKind:string;status:string;configHash:string;approvalHash:string|null;validatedHash:string|null;validationReport:unknown;definition:unknown};
function record(value:unknown):Record<string,unknown>|undefined{return value!==null&&typeof value==='object'&&!Array.isArray(value)?value as Record<string,unknown>:undefined}
export function isProbeValidationCurrent(row:ApprovalTemplate){
 const report=record(row.validationReport),definition=record(row.definition),rule=record(definition?.rule),native=record(rule?.nativeTemplate);
 if(row.validatedHash!==row.configHash||report?.passed!==true)return false;
 if(row.sourceKind==='NUCLEI_LIBRARY')return !!native&&typeof native.raw==='string'&&Buffer.byteLength(native.raw)<=65536&&typeof native.sha256==='string'&&/^[a-f0-9]{64}$/.test(native.sha256)&&createHash('sha256').update(native.raw).digest('hex')===native.sha256&&typeof native.engineVersion==='string'&&/^\d+\.\d+\.\d+$/.test(native.engineVersion)&&report.validationKind==='NATIVE_TEMPLATE_COMPILE'&&report.templateSha256===native.sha256&&report.engineVersion===native.engineVersion;
 return ['LOCAL','NUCLEI_HTTP'].includes(row.sourceKind)&&!native;
}
export function isApprovedProbeTemplate(row:ApprovalTemplate){return row.status==='APPROVED'&&!!row.approvalHash&&row.approvalHash===row.configHash&&isProbeValidationCurrent(row)}
// Call inside the same transaction as the allowance or result write. Shared row
// locks prevent a concurrent stop/change from committing before that write.
export async function assertApprovedActiveSources(tx:Prisma.TransactionClient,target:{assetId:string;inventory:any}){
 const inventory=target.inventory,parsed=activeSourcePins.safeParse(inventory?.activeSources),active=inventory?.active;if(!parsed.success||!Array.isArray(active?.endpoints)||!Array.isArray(active?.checks)||parsed.data.endpoints.length!==active.endpoints.length||parsed.data.templates.length!==active.checks.length)throw new ConflictException('缺少与本次检查对应的目标和模板批准版本');
 const endpointIds=parsed.data.endpoints.map(row=>row.id).sort(),templateIds=parsed.data.templates.map(row=>row.id).sort();
 await tx.$queryRaw`SELECT id FROM "ScanEndpoint" WHERE id = ANY(${endpointIds}::text[]) ORDER BY id FOR SHARE`;
 await tx.$queryRaw`SELECT id FROM "ProbeTemplate" WHERE id = ANY(${templateIds}::text[]) ORDER BY id FOR SHARE`;
 const endpoints=await tx.scanEndpoint.findMany({where:{id:{in:endpointIds}}}),templates=await tx.probeTemplate.findMany({where:{id:{in:templateIds}}}),endpointById=new Map(endpoints.map(row=>[row.id,row])),templateById=new Map(templates.map(row=>[row.id,row]));
 for(const [index,pin] of parsed.data.endpoints.entries()){
  const row=endpointById.get(pin.id);if(!row||row.assetId!==target.assetId||row.status!=='APPROVED'||row.version!==pin.version||row.approvalHash!==pin.approvalHash||!row.approvedAddresses.length)throw new ConflictException('目标范围批准已修改、停止或不属于当前资产，请重新核对计划');
  const expected={hostname:row.hostname,port:row.port,protocol:row.protocol,addresses:row.approvedAddresses,allowedPaths:row.allowedPaths,excludedPaths:row.excludedPaths};if(!isDeepStrictEqual(expected,active.endpoints[index]))throw new ConflictException('冻结网络范围与已批准目标不一致，不能继续执行');
 }
 for(const [index,pin] of parsed.data.templates.entries()){
  const row=templateById.get(pin.id);if(!row||!isApprovedProbeTemplate(row)||row.version!==pin.version||row.configHash!==pin.approvalHash)throw new ConflictException('模板校验或批准已修改、停止，请重新核对计划');
  const definition=row.definition as any,expected=instantiateProbeCheck(definition,active.endpoints);if(!isDeepStrictEqual(expected,active.checks[index]))throw new ConflictException('冻结检查条件与已批准模板不一致，不能继续执行');
 }
 return parsed.data;
}
