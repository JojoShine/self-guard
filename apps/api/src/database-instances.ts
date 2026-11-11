import {databaseAuditSourceFormats,databaseCapabilities} from './database-capabilities';
import {Body,Controller,Get,Inject,Param,Patch,Post,Query,Req,UseGuards,NotFoundException,ConflictException,ForbiddenException,BadRequestException} from '@nestjs/common';
import {z} from 'zod';import {Prisma} from '@prisma/client';
import {AuthGuard,allow} from './auth';import {Db} from './db';import {assertScope,assertEvidence,assetScope} from './scope';import {parse,pageInput,text} from './validation';import {engines,SecurityRequest,SecurityUser} from './database-contract';
export const instanceInput=z.object({name:text,engine:z.enum(engines),stableKey:z.string().trim().min(1).max(200),version:z.string().trim().max(128).optional(),owner:text,business:text.nullable().optional(),hostIds:z.array(z.string().uuid()).max(100).default([]),auditSources:z.array(z.object({assetId:z.string().uuid(),path:z.string().startsWith('/').max(4096),format:z.enum(databaseAuditSourceFormats)}).strict()).max(20).default([]),endpoints:z.array(z.object({address:z.string().trim().min(1).max(253).regex(/^[a-zA-Z0-9.:-]+$/),port:z.number().int().min(1).max(65535)}).strict()).max(20).default([])}).strict();
export function instanceScope(user:Pick<SecurityUser,'role'|'dataScope'>):Prisma.DatabaseInstanceWhereInput{
 if(user.role==='ADMIN'||!user.dataScope?.restricted)return {};
 return {OR:[{business:{in:user.dataScope.businesses||[]}},{id:{in:user.dataScope.databaseInstanceIds||[]}}]};
}
export async function assertInstanceScope(tx:Pick<Prisma.TransactionClient,'databaseInstance'>,user:Pick<SecurityUser,'role'|'dataScope'>,id:string){const row=await tx.databaseInstance.findFirst({where:{AND:[{id},instanceScope(user)]}});if(!row)throw new NotFoundException('数据库实例不存在或不在授权范围');return row;}
export function assertInstanceBusiness(user:SecurityUser,business:string|null|undefined){if(user.role!=='ADMIN'&&user.dataScope?.restricted&&(!business||!user.dataScope.businesses?.includes(business)))throw new ForbiddenException('不能将实例分配到未授权业务');}
@Controller('database-instances') @UseGuards(AuthGuard)
export class DatabaseInstancesController{
 constructor(@Inject(Db)private db:Db){}
 @Get('capabilities')capabilities(@Req()req:SecurityRequest){assertEvidence(req.user);return{items:engines.map(databaseCapabilities)}}
 @Get(':id/collection')async collection(@Req()req:SecurityRequest,@Param('id')id:string){
  assertEvidence(req.user);
  const instance=await assertInstanceScope(this.db,req.user,id),now=new Date(),recent=new Date(now.getTime()-3600000);
  const hosts=await this.db.asset.findMany({where:{AND:[assetScope(req.user),{id:{in:instance.hostIds},archivedAt:null}]},select:{id:true,lastSeen:true,inventory:true}});
  const hostIds=hosts.map(host=>host.id),sources=instanceInput.shape.auditSources.parse(instance.auditSources).filter(source=>hostIds.includes(source.assetId));
  const where:Prisma.DatabaseAuditWhereInput={instanceId:id,collectorAssetId:{in:hostIds}};
  const execution:Prisma.DatabaseAuditWhereInput={NOT:{details:{path:['execution'],equals:Prisma.DbNull}}};
  const connection:Prisma.DatabaseAuditWhereInput={...where,operation:{in:['LOGIN','LOGOUT']}};
  const statement:Prisma.DatabaseAuditWhereInput={...where,...execution};
  const[recentEvents,latest,connectionCount,latestConnection,statementCount,latestStatement,retainedTextRecords,operationCount]=await Promise.all([
   this.db.databaseAudit.count({where:{...where,timestamp:{gte:recent,lte:now}}}),
   this.db.databaseAudit.findFirst({where:{...where,timestamp:{lte:now}},orderBy:{timestamp:'desc'},select:{timestamp:true}}),
   this.db.databaseAudit.count({where:{...connection,timestamp:{gte:recent,lte:now}}}),
   this.db.databaseAudit.findFirst({where:{...connection,timestamp:{lte:now}},orderBy:{timestamp:'desc'},select:{timestamp:true}}),
   this.db.databaseAudit.count({where:{...statement,timestamp:{gte:recent,lte:now}}}),
   this.db.databaseAudit.findFirst({where:{...statement,timestamp:{lte:now}},orderBy:{timestamp:'desc'},select:{timestamp:true}}),
   this.db.databaseSqlEvidence.count({where:{expiresAt:{gt:now},audit:{is:{...where,timestamp:{lte:now}}}}}),
   this.db.databaseAudit.count({where:{...where,operation:{notIn:['LOGIN','LOGOUT']},details:{path:['execution'],equals:Prisma.DbNull},timestamp:{gte:recent,lte:now}}}),
  ]);
  const reporting=hosts.filter(host=>{
   const inventory=host.inventory;
   // Enrollment also sets lastSeen, but only a collector report has observedAt.
   return host.lastSeen&&host.lastSeen.getTime()>=now.getTime()-90000&&inventory&&typeof inventory==='object'&&!Array.isArray(inventory)&&typeof inventory.observedAt==='string'&&Number.isFinite(Date.parse(inventory.observedAt));
  }).length;
  const capabilities=databaseCapabilities(instance.engine);
  const statementHosts=new Set(sources.filter(source=>source.format!=='postgresql-csv-sql'&&capabilities.rawStatement.formats.includes(source.format)).map(source=>source.assetId));
  const statementCollectorsReady=hosts.filter(host=>{
   const inventory=host.inventory;if(!statementHosts.has(host.id)||!inventory||typeof inventory!=='object'||Array.isArray(inventory))return false;
   const diagnostics=inventory.agentDiagnostics;if(!diagnostics||typeof diagnostics!=='object'||Array.isArray(diagnostics))return false;
   return Array.isArray(diagnostics.capabilities)&&diagnostics.capabilities.includes('database-statements-v1');
  }).length;
  return {checkedAt:now.toISOString(),windowMinutes:60,sources:sources.length,hosts:{authorized:hosts.length,reporting},recentEvents,latestEventAt:latest?.timestamp.toISOString()||null,capabilities,connections:{recentEvents:connectionCount,latestEventAt:latestConnection?.timestamp.toISOString()||null},statements:{collectors:{required:statementHosts.size,ready:statementCollectorsReady},sources:sources.filter(source=>capabilities.rawStatement.formats.includes(source.format)).length,recentEvents:statementCount,latestEventAt:latestStatement?.timestamp.toISOString()||null,retainedTextRecords},operations:{recentEvents:operationCount}};
 }
 @Get()async list(@Req()req:SecurityRequest,@Query()query:unknown){const v=parse(pageInput.extend({engine:z.enum(engines).optional(),includeArchived:z.enum(['true','false']).default('false')}),query);const where:Prisma.DatabaseInstanceWhereInput={AND:[instanceScope(req.user),{...(v.includeArchived==='false'?{archivedAt:null}:{}),...(v.engine?{engine:v.engine}:{}),...(v.q?{OR:[{name:{contains:v.q,mode:'insensitive'}},{stableKey:{contains:v.q,mode:'insensitive'}},{owner:{contains:v.q,mode:'insensitive'}}]}:{})}]};const[items,total]=await Promise.all([this.db.databaseInstance.findMany({where,orderBy:[{updatedAt:'desc'},{id:'asc'}],take:v.pageSize,skip:(v.page-1)*v.pageSize}),this.db.databaseInstance.count({where})]);return{items,total,canManage:['ADMIN','ANALYST'].includes(req.user.role)};}
 @Get(':id')async detail(@Req()req:SecurityRequest,@Param('id')id:string){return assertInstanceScope(this.db,req.user,id);}
 @Post()async create(@Req()req:SecurityRequest,@Body()body:unknown){allow(req,['ADMIN','ANALYST']);assertEvidence(req.user);const v=parse(instanceInput,body);assertInstanceBusiness(req.user,v.business);for(const source of v.auditSources){if(!v.hostIds.includes(source.assetId))throw new BadRequestException('审计来源必须关联授权采集主机');assertDatabaseRuleEngine(v.engine,{service:source.format});}return this.db.$transaction(async tx=>{for(const id of v.hostIds)await assertScope(tx,req.user,'assets',id);const row=await tx.databaseInstance.create({data:v});if(v.business)await tx.businessGroup.upsert({where:{name:v.business},create:{name:v.business},update:{}});await tx.audit.create({data:{actor:req.user.email,action:'CREATE',resource:'database-instances',resourceId:row.id,detail:v}});return row;});}
 @Patch(':id')async update(@Req()req:SecurityRequest,@Param('id')id:string,@Body()body:unknown){allow(req,['ADMIN','ANALYST']);assertEvidence(req.user);const v=parse(instanceInput.omit({engine:true,stableKey:true}).partial().extend({hostIds:instanceInput.shape.hostIds.removeDefault().optional(),auditSources:instanceInput.shape.auditSources.removeDefault().optional(),endpoints:instanceInput.shape.endpoints.removeDefault().optional(),archived:z.boolean().optional(),expectedUpdatedAt:z.string().datetime()}),body);return this.db.$transaction(async tx=>{const old=await assertInstanceScope(tx,req.user,id);if(v.business!==undefined)assertInstanceBusiness(req.user,v.business);for(const host of v.hostIds||[])await assertScope(tx,req.user,'assets',host);for(const source of v.auditSources||[])await assertScope(tx,req.user,'assets',source.assetId);for(const source of v.auditSources||old.auditSources as {assetId:string;format:string}[]){if(!(v.hostIds||old.hostIds).includes(source.assetId))throw new BadRequestException('审计来源必须关联授权采集主机');assertDatabaseRuleEngine(old.engine,{service:source.format});}const{archived,expectedUpdatedAt,...data}=v;const result=await tx.databaseInstance.updateMany({where:{id,updatedAt:new Date(expectedUpdatedAt)},data:{...data,...(archived!==undefined?{archivedAt:archived?new Date():null}:{})}});if(!result.count)throw new ConflictException('实例已变化，请刷新');await tx.audit.create({data:{actor:req.user.email,action:'UPDATE',resource:'database-instances',resourceId:id,detail:{before:{business:old.business,owner:old.owner,hostIds:old.hostIds},after:v}}});return tx.databaseInstance.findUniqueOrThrow({where:{id}});});}
}

export function assertDatabaseRuleEngine(engine:string,config:Record<string,unknown>){
 const key=String(config.key||'');if((key.startsWith('MYSQL_')&&engine!=='mysql')||(key.startsWith('POSTGRES_')&&engine!=='postgresql'))throw new BadRequestException('配置检查与实例数据库类型不兼容');
 if((String(config.service).startsWith('dm-')&&engine!=='dm')||(String(config.service).startsWith('oracle-')&&engine!=='oracle')||(String(config.service).startsWith('postgresql')&&engine!=='postgresql')||(String(config.service).startsWith('mysql')&&engine!=='mysql')||(String(config.service).startsWith('sqlserver-')&&engine!=='sqlserver')||(String(config.service).startsWith('redis-')&&engine!=='redis')||(String(config.service).startsWith('kingbase-')&&engine!=='kingbase')||(String(config.service).startsWith('vastbase-')&&engine!=='vastbase'))throw new BadRequestException('原生审计格式与实例类型不兼容');
 if((config.service==='mysql'&&engine!=='mysql')||(config.service==='postgresql'&&engine!=='postgresql'))throw new BadRequestException('原生日志格式与实例类型不兼容');
 if(Array.isArray(config.engines)&&!config.engines.includes(engine))throw new BadRequestException('规则适用数据库不包含该实例类型');
}
