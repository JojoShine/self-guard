import {ConflictException} from '@nestjs/common';
import {assertGlobal,assertEvidence} from './scope';
import {isDeepStrictEqual} from 'node:util';
import {freezeExecutionIdentity,frozenExecutionIdentity,executionScopeAllows,type FrozenExecutionIdentity} from './scan-execution-contracts';
export class ScanAuthorizationError extends ConflictException{}
export async function executionAuthorization(db:any,plan:any,run?:any){
 if(db.$queryRaw)await db.$queryRaw`SELECT id FROM "User" WHERE id=${plan.creatorId} FOR SHARE`;
 const user=await db.user.findUnique({where:{id:plan.creatorId}});if(!user||user.disabled||!['ADMIN','ANALYST'].includes(user.role))throw new ScanAuthorizationError('计划负责人已停用、删除或失去检测权限');try{assertGlobal(user);assertEvidence(user)}catch{throw new ScanAuthorizationError('计划负责人数据范围或证据权限已被收回')}
 let identity:FrozenExecutionIdentity|null=null;
 if(plan.executionIdentityId){
  if(db.$queryRaw)await db.$queryRaw`SELECT id FROM "ScanExecutionIdentity" WHERE id=${plan.executionIdentityId} FOR SHARE`;
  const row=await db.scanExecutionIdentity.findUnique({where:{id:plan.executionIdentityId}});if(!row?.enabled||row.version!==plan.executionIdentityVersion)throw new ScanAuthorizationError('扫描执行身份已停用或授权版本变化，请管理员重新预览并绑定');
  try{identity=freezeExecutionIdentity(row)}catch{throw new ScanAuthorizationError('扫描执行身份的授权内容不完整，不能执行')}
 }
 if(run!==undefined){
  if(identity){const frozen=frozenExecutionIdentity.safeParse(run.executionIdentity);if(!frozen.success||frozen.data.id!==identity.id||frozen.data.version!==identity.version||frozen.data.approvedBy!==identity.approvedBy||frozen.data.approvedAt!==identity.approvedAt||!isDeepStrictEqual(frozen.data.scope,identity.scope))throw new ScanAuthorizationError('本次冻结的执行身份与当前授权不一致，不能替换旧运行的授权')}
  else if(run.executionIdentity!=null)throw new ScanAuthorizationError('本次运行的执行身份已被替换，不能退回负责人授权');
 }
 return {owner:user,identity};
}
export async function executionOwner(db:any,plan:any,run?:any){return (await executionAuthorization(db,plan,run)).owner}
export function assertExecutionAsset(authorization:{identity:FrozenExecutionIdentity|null},asset:{id:string},businessId?:string|null){if(authorization.identity&&!executionScopeAllows(authorization.identity.scope,asset,businessId))throw new ScanAuthorizationError('目标当前不在扫描执行身份的明确授权范围内')}
