import {assertApprovedActiveSources} from './active-scan-pins';
import {Prisma} from '@prisma/client';
import {ConflictException} from '@nestjs/common';import {isIP} from 'node:net';import {Db} from './db';import {executionAuthorization,assertExecutionAsset} from './scan-authorization';import {resolveScanScope} from './construction-contracts';import {planScanTiming,scanWindowOpen} from './scan-timing';
export async function claimScanRun(db:Db,id:string,leaseId:string){return db.$transaction(async tx=>{
 await tx.$queryRaw`SELECT pg_advisory_xact_lock(hashtext('selfguard-scan-slots-v1'))::text`;
 const [{now}]=await tx.$queryRaw<Array<{now:Date}>>`SELECT clock_timestamp() AS now`;
 const current=await tx.scanRun.findFirst({where:{id,OR:[{status:'QUEUED'},{status:'RUNNING',leaseUntil:{lt:now}}]}});if(!current)return false;
 if(await tx.scanRun.count({where:{status:'RUNNING',leaseUntil:{gt:now}}})>=4)return false;
 const changed=await tx.scanRun.updateMany({where:{id,status:current.status,...(current.status==='RUNNING'?{leaseUntil:{lt:now}}:{})},data:{status:'RUNNING',leaseId,leaseUntil:new Date(now.getTime()+300000)}});return changed.count===1;
 },{timeout:30000})}
type Allowance={allowed:boolean;reason:'GRANTED'|'RATE_WAIT'|'TARGET_REQUEST_LIMIT';retryAfterMs:number;issuedAt?:Date};
function frozenKeys(inventory:any){const endpoints=inventory?.active?.endpoints;if(!Array.isArray(endpoints)||!endpoints.length||endpoints.length>100)throw new ConflictException('缺少本次运行冻结的网络目标');const keys=new Set<string>();for(const endpoint of endpoints){if(!Number.isInteger(endpoint?.port)||endpoint.port<1||endpoint.port>65535||!Array.isArray(endpoint.addresses)||!endpoint.addresses.length||endpoint.addresses.length>32)throw new ConflictException('冻结目标的地址或端口无效');for(const address of endpoint.addresses){const family=typeof address==='string'?isIP(address):0;if(!family)throw new ConflictException('冻结目标缺少明确地址');keys.add((family===6?'['+address+']':address)+':'+endpoint.port)}}return keys;}
export async function assertActiveScanTarget(tx:Prisma.TransactionClient,runId:string,targetId:string,leaseId:string){
  await tx.$queryRaw`SELECT id FROM "ScanRun" WHERE id=${runId} FOR UPDATE`;
  const [{now}]=await tx.$queryRaw<Array<{now:Date}>>`SELECT clock_timestamp() AS now`;
  const run=await tx.scanRun.findFirst({where:{id:runId,status:'RUNNING',leaseId,leaseUntil:{gt:now}}});if(!run)throw new ConflictException('扫描已取消或执行租约无效');
  const plan=await tx.scanPlan.findUniqueOrThrow({where:{id:run.planId},select:{creatorId:true,enabled:true,kind:true,executionIdentityId:true,executionIdentityVersion:true}});if(!plan.enabled||plan.kind!=='ACTIVE')throw new ConflictException('网络扫描计划未启用');const authorization=await executionAuthorization(tx,plan,run);if(!scanWindowOpen(planScanTiming({timing:(run.timing as any)?.policy}),now))throw new ConflictException('当前已离开允许扫描的窗口');
  const target=await tx.scanTarget.findFirst({where:{id:targetId,runId,status:'RUNNING'},select:{id:true,assetId:true,inventory:true,httpRequests:true}});if(!target)throw new ConflictException('扫描目标未在执行中');
  await tx.$queryRaw`SELECT id FROM "Asset" WHERE id=${target.assetId} FOR SHARE`;
  const asset=await tx.asset.findUnique({where:{id:target.assetId}});if(!asset||asset.archivedAt)throw new ConflictException('资产已归档或删除');const business=asset.business?await tx.businessGroup.findUnique({where:{name:asset.business}}):null;assertExecutionAsset(authorization,asset,business?.id);
  const scope=resolveScanScope(run.scope as any,[{id:asset.id,businessId:business?.id||null,tags:asset.tags,type:'SERVICE',archivedAt:asset.archivedAt,inventoryAt:null}],new Set([asset.id]),now,false);if(!scope.selected.length)throw new ConflictException('目标已不在允许的扫描范围');
 await assertApprovedActiveSources(tx,target);
 return {run,target,now,allowed:frozenKeys(target.inventory)};
}
// Called by the supervisor, never directly exposed to a scanning process or user.
// Database time and one advisory lock provide strict spacing across all workers.
export async function acquireHttpAllowance(db:Db,runId:string,targetId:string,leaseId:string,keys:string[]):Promise<Allowance>{
 if(!Array.isArray(keys)||!keys.length||keys.length>32||new Set(keys).size!==keys.length)throw new ConflictException('请求额度的目标范围无效');
 return db.$transaction(async tx=>{
  await tx.$queryRaw`SELECT pg_advisory_xact_lock(hashtext('selfguard-scan-http-v1'))::text`;
  const {run,target,now,allowed}=await assertActiveScanTarget(tx,runId,targetId,leaseId);
  if(keys.some(key=>!allowed.has(key)))throw new ConflictException('请求地址不属于本次冻结目标');
  if(target.httpRequests>=300)return {allowed:false,reason:'TARGET_REQUEST_LIMIT',retryAfterMs:0};
  const bucketKeys=['GLOBAL',...keys.map(key=>'ENDPOINT:'+key)],buckets=await tx.scanBudgetBucket.findMany({where:{key:{in:bucketKeys}}}),waitUntil=Math.max(now.getTime(),...buckets.map(bucket=>bucket.nextAllowedAt.getTime()));
  if(waitUntil>now.getTime())return {allowed:false,reason:'RATE_WAIT',retryAfterMs:waitUntil-now.getTime()};
  for(const key of bucketKeys){const nextAllowedAt=new Date(now.getTime()+(key==='GLOBAL'?20:500));await tx.scanBudgetBucket.upsert({where:{key},create:{key,nextAllowedAt},update:{nextAllowedAt}})}
  await tx.scanTarget.update({where:{id:target.id},data:{httpRequests:{increment:1}}});await tx.scanRun.update({where:{id:run.id},data:{leaseUntil:new Date(now.getTime()+300000)}});
  return {allowed:true,reason:'GRANTED',retryAfterMs:0,issuedAt:now};
 },{timeout:30000});
}
