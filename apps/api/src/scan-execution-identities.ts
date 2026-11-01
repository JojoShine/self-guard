import {Body,Controller,Get,Post,Patch,Param,Query,Req,UseGuards,Inject,ConflictException,NotFoundException,ForbiddenException} from '@nestjs/common';
import {isDeepStrictEqual} from 'node:util';import {z} from 'zod';
import {Db} from './db';import {AuthGuard,allow} from './auth';import {assertGlobal,assertEvidence} from './scope';import {parse} from './validation';import {componentPageInput} from './construction-contracts';import {executionIdentityInput,executionScopeInput,freezeExecutionIdentity} from './scan-execution-contracts';

function read(req:any){assertGlobal(req.user);assertEvidence(req.user)}
function write(req:any){allow(req,['ADMIN']);read(req)}
async function grantAdministrator(db:any,user:any){
 if(user.role!=='ADMIN')throw new ForbiddenException('只有管理员可以授予或变更扫描执行身份');
 await db.$queryRaw`SELECT id FROM "User" WHERE id=${user.id} FOR SHARE`;
 const current=await db.user.findUnique({where:{id:user.id}});if(!current||current.disabled||current.role!=='ADMIN')throw new ForbiddenException('管理员当前授权已变化，不能继续授予扫描执行身份');
}
async function validateScope(db:any,scope:z.infer<typeof executionScopeInput>){
 const [assets,businesses]=await Promise.all([db.asset.count({where:{id:{in:scope.assetIds},archivedAt:null}}),db.businessGroup.count({where:{id:{in:scope.businessIds}}})]);
 if(assets!==scope.assetIds.length||businesses!==scope.businessIds.length)throw new ConflictException('授权选择中包含已删除或归档的对象，请重新选择现有资产和业务');
}
// Only an administrator can create or renew a service grant. Omitting this field
// preserves the previous binding and never silently renews an obsolete version.
export async function bindExecutionIdentity(db:any,user:any,id:string|null|undefined,previous?:any,expectedVersion?:number){
 if(id===undefined){if(expectedVersion!==undefined)throw new ConflictException('授权版本需要与明确选择的执行身份一起提交');return {executionIdentityId:previous?.executionIdentityId??null,executionIdentityVersion:previous?.executionIdentityVersion??null}}
 if(id!==null||previous?.executionIdentityId)await grantAdministrator(db,user);
 if(id===null){if(expectedVersion!==undefined)throw new ConflictException('负责人执行方式不使用专用身份授权版本');return {executionIdentityId:null,executionIdentityVersion:null}}
 await db.$queryRaw`SELECT id FROM "ScanExecutionIdentity" WHERE id=${id} FOR SHARE`;
 const row=await db.scanExecutionIdentity.findUnique({where:{id}});if(!row?.enabled)throw new ConflictException('请选择仍启用的扫描执行身份');freezeExecutionIdentity(row);
 if(row.version!==expectedVersion)throw new ConflictException('执行身份的授权版本已变化，请刷新选项并重新预览；不能自动授予新范围');
 return {executionIdentityId:row.id,executionIdentityVersion:row.version};
}
export function executionBindingValid(plan:any){return !plan.executionIdentityId||!!plan.executionIdentity?.enabled&&plan.executionIdentity.version===plan.executionIdentityVersion}

@Controller('scan-execution-identities') @UseGuards(AuthGuard)
export class ScanExecutionIdentitiesController{
 constructor(@Inject(Db)private db:Db){}
 @Get('options')async options(@Req()req:any){read(req);return {canEdit:req.user.role==='ADMIN',assets:await this.db.asset.findMany({where:{archivedAt:null},orderBy:[{hostname:'asc'},{id:'asc'}],select:{id:true,hostname:true,business:true}}),businesses:await this.db.businessGroup.findMany({orderBy:{name:'asc'},select:{id:true,name:true}})}}
 @Get()async list(@Req()req:any,@Query()query:unknown){read(req);const value=parse(componentPageInput,query),where=value.q?{name:{contains:value.q,mode:'insensitive' as const}}:{};const [items,total]=await Promise.all([this.db.scanExecutionIdentity.findMany({where,orderBy:[{createdAt:'desc'},{id:'asc'}],skip:(value.page-1)*value.pageSize,take:value.pageSize,include:{_count:{select:{plans:true}}}}),this.db.scanExecutionIdentity.count({where})]);return {items,total}}
 @Post()async create(@Req()req:any,@Body()body:unknown){write(req);const value=parse(executionIdentityInput,body);return this.db.$transaction(async tx=>{await grantAdministrator(tx,req.user);await validateScope(tx,value.scope);const row=await tx.scanExecutionIdentity.create({data:{name:value.name,scope:value.scope,enabled:value.enabled??true,approvedBy:req.user.id}});await tx.audit.create({data:{actor:req.user.email,action:'GRANT_SCAN_EXECUTION_IDENTITY',resource:'scan-execution-identities',resourceId:row.id,detail:{name:row.name,scope:value.scope,version:row.version,enabled:row.enabled}}});return row})}
 @Patch(':id')async patch(@Req()req:any,@Param('id')id:string,@Body()body:unknown){
  write(req);const value=parse(executionIdentityInput.partial().extend({expectedVersion:z.number().int().positive(),expectedUpdatedAt:z.string().datetime({offset:true})}).strict().refine(input=>input.name!==undefined||input.scope!==undefined||input.enabled!==undefined,'请提供需要修改的内容'),body);
  return this.db.$transaction(async tx=>{await grantAdministrator(tx,req.user);await tx.$queryRaw`SELECT id FROM "ScanExecutionIdentity" WHERE id=${id} FOR UPDATE`;const old=await tx.scanExecutionIdentity.findUnique({where:{id}});if(!old)throw new NotFoundException('扫描执行身份不存在');if(old.version!==value.expectedVersion||old.updatedAt.getTime()!==Date.parse(value.expectedUpdatedAt))throw new ConflictException('执行身份已被其他操作更新，请刷新后核对');if(value.scope)await validateScope(tx,value.scope);
   const authorizationChanged=value.scope!==undefined&&!isDeepStrictEqual(parse(executionScopeInput,old.scope),value.scope)||value.enabled!==undefined&&value.enabled!==old.enabled;
   const row=await tx.scanExecutionIdentity.update({where:{id},data:{name:value.name,scope:value.scope,enabled:value.enabled,...(authorizationChanged?{version:{increment:1},approvedBy:req.user.id,approvedAt:new Date()}: {})}});
   await tx.audit.create({data:{actor:req.user.email,action:authorizationChanged?'CHANGE_SCAN_EXECUTION_GRANT':'RENAME_SCAN_EXECUTION_IDENTITY',resource:'scan-execution-identities',resourceId:id,detail:{previousVersion:old.version,version:row.version,enabled:row.enabled,scope:row.scope,authorizationChanged}}});return {...row,authorizationChanged};
  });
 }
}
