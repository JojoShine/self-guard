import {investigationContext} from './investigation';
import {recordAssetChange} from "./asset-history";
import {assertScope,assertLinks,assertEvidence,assertGlobal,resourceWhere,restricted} from "./scope";
import {Controller,Get,Post,Patch,Param,Body,Query,Req,UseGuards,Inject,BadRequestException,NotFoundException,ConflictException} from '@nestjs/common';
import {Platform} from './platform';import {AuthGuard,allow} from './auth';import {parse,text,pageInput} from './validation';import {z} from 'zod';
@Controller('workflows') @UseGuards(AuthGuard)
export class WorkflowsController {
 constructor(@Inject(Platform) private p:Platform){}
 @Post('assets/:id/archive') async archive(@Param('id') id:string,@Body() body:unknown,@Req() req:any){
  await assertScope(this.p.db,req.user,"assets",id);
  allow(req,['ADMIN','ANALYST']);const v=parse(z.object({archived:z.boolean()}).strict(),body);
  await assertLinks(this.p.db,req.user,v);
  return this.p.db.$transaction(async tx=>{if(await tx.task.count({where:{assetId:id,status:{in:['RUNNING','UNKNOWN']}}}))throw new ConflictException('资产存在执行中或结果未知的任务');
   await tx.$queryRaw`SELECT id FROM "Asset" WHERE id=${id} FOR UPDATE`;
   const previous=await tx.asset.findUniqueOrThrow({where:{id}});
   const item=await tx.asset.update({where:{id},data:{archivedAt:v.archived?new Date():null}});
   await recordAssetChange(tx,id,previous,item,req.user.email);
   await this.p.audit(tx,req.user.email,v.archived?'ARCHIVE':'RESTORE','assets',id);return {id:item.id,archivedAt:item.archivedAt};});
 }
 @Patch('findings/:id/triage') async triage(@Param('id') id:string,@Body() body:unknown,@Req() req:any){
  await assertScope(this.p.db,req.user,"findings",id);
  allow(req,['ADMIN','ANALYST']);const v=parse(z.object({read:z.boolean().optional(),relatedRiskId:z.string().uuid().nullable().optional(),confirmed:z.boolean().optional(),dueAt:z.string().datetime().optional(),reason:z.string().trim().min(1).max(4000).optional()}).strict(),body);
  await assertLinks(this.p.db,req.user,v);
  return this.p.db.$transaction(async tx=>{const f=await tx.finding.findUnique({where:{id}});if(!f)throw new NotFoundException();
   if(v.relatedRiskId){const risk=await tx.finding.findUnique({where:{id:v.relatedRiskId}});if(f.kind!=='ALERT'||!risk||risk.kind!=='RISK')throw new BadRequestException('仅告警可关联已存在风险');}
   if(v.dueAt&&!v.reason)throw new BadRequestException('延期需要原因');
   const data:any={...(v.read!==undefined?{readAt:v.read?new Date():null}:{}),...(v.relatedRiskId!==undefined?{relatedRiskId:v.relatedRiskId}:{}),...(v.dueAt?{dueAt:new Date(v.dueAt),reason:v.reason}:{})};
   if(v.confirmed){if(f.kind!=='RISK'||f.status!=='OPEN')throw new ConflictException('仅新风险可以确认');data.status='CONFIRMED';}
   const changed=await tx.finding.updateMany({where:{id,updatedAt:f.updatedAt},data});if(!changed.count)throw new ConflictException('记录已变化');
   await this.p.audit(tx,req.user.email,'TRIAGE','findings',id,v);return tx.finding.findUnique({where:{id}});
  });
 }
 @Patch('incidents/:id/context') async context(@Param('id') id:string,@Body() body:unknown,@Req() req:any){
  await assertScope(this.p.db,req.user,"incidents",id);
  allow(req,['ADMIN','ANALYST']);const v=parse(z.object({type:text.optional(),assetIds:z.array(z.string().uuid()).max(100).optional(),taskIds:z.array(z.string().uuid()).max(100).optional(),remainingRisks:z.string().max(16000).optional()}).strict(),body);
  await assertLinks(this.p.db,req.user,v);
  return this.p.db.$transaction(async tx=>{for(const [key,model]of [['assetIds','asset'],['taskIds','task']]as const){const ids=v[key];if(ids&&await(tx[model]as any).count({where:{id:{in:ids}}})!==new Set(ids).size)throw new BadRequestException('关联记录不存在');}
   const item=await tx.incident.update({where:{id},data:v});await this.p.audit(tx,req.user.email,'CONTEXT','incidents',id,v);return item;});
 }
 @Get(':resource/:id/context') async investigation(@Param('resource') resource:string,@Param('id') id:string,@Query()query:unknown,@Req()req:any){
  const v=parse(z.object({page:z.coerce.number().int().min(1).default(1),pageSize:z.coerce.number().int().min(1).max(100).default(15)}).strict(),query);return investigationContext(this.p.db,req.user,resource,id,v.page,v.pageSize);
 }
 @Get(':resource/:id/relations') async relations(@Param('resource') resource:string,@Param('id') id:string,@Req() req:any){
  if(!['assets','findings','incidents','tasks'].includes(resource))throw new NotFoundException();const entity=await this.p.get(resource,id,req.user);
  const assetId=resource==='assets'?id:entity.assetId;const findingId=resource==='findings'?id:entity.findingId;
  const findingRelation=resource==='incidents'?{links:{some:{incidentId:id}}}:assetId?{assetId}:null;
  const findings=findingRelation?await this.p.db.finding.findMany({where:{AND:[findingRelation,await resourceWhere(this.p.db,req.user,'findings')]},orderBy:[{updatedAt:'desc'},{id:'asc'}],take:100}):[];
  const tasks=await this.p.db.task.findMany({where:{AND:[assetId?{assetId}:findingId?{findingId}:{id:{in:entity.taskIds||[]}},await resourceWhere(this.p.db,req.user,'tasks')]},select:{id:true,title:true,status:true,assetId:true,findingId:true},take:100});
  const incidents=await this.p.db.incident.findMany({where:{AND:[resource==='incidents'?{id}:findingId?{links:{some:{findingId}}}:assetId?{OR:[{assetIds:{has:assetId}},{links:{some:{finding:{assetId}}}}]}:{id:{in:[]}},await resourceWhere(this.p.db,req.user,'incidents')]},include:{links:true},take:100});
  return {findings,tasks,incidents:incidents.map(i=>this.p.incidentShape(i)),limit:100};
 }
 @Get(':resource/:id/timeline') async timeline(@Param('resource') resource:string,@Param('id') id:string,@Req() req:any={user:undefined}){
  if(!['assets','findings','incidents','tasks'].includes(resource))throw new NotFoundException();await this.p.get(resource,id,req.user);
  assertEvidence(req.user);
  const [audit,comments]=await Promise.all([this.p.db.audit.findMany({where:{resource,resourceId:id},take:200,orderBy:{createdAt:'desc'}}),this.p.db.comment.findMany({where:{resource,resourceId:id},take:200,orderBy:{createdAt:'desc'}})]);
  return {items:[...audit.map(x=>({id:x.id,type:'ACTION',actor:x.actor,action:x.action,createdAt:x.createdAt})),...comments.map(x=>({id:x.id,type:'COMMENT',actor:x.author,action:x.body,createdAt:x.createdAt}))].sort((a,b)=>b.createdAt.getTime()-a.createdAt.getTime()),limit:400};
 }
 @Post('tasks/:id/cancel') async cancel(@Param('id') id:string,@Body() body:unknown,@Req() req:any){
  await assertScope(this.p.db,req.user,"tasks",id);
  allow(req,['ADMIN','OPERATOR']);const v=parse(z.object({reason:text}).strict(),body);
  await assertLinks(this.p.db,req.user,v);
  return this.p.db.$transaction(async tx=>{const count=await tx.task.updateMany({where:{id,status:{in:['PENDING','APPROVED']}},data:{status:'CANCELLED',reason:v.reason}});if(!count.count)throw new ConflictException('仅未执行任务可以取消，已完成变更不会撤销');await this.p.audit(tx,req.user.email,'CANCEL','tasks',id,v);return {ok:true};});
 }
 @Post('tasks/:id/window') async window(@Param('id') id:string,@Body() body:unknown,@Req() req:any){
  await assertScope(this.p.db,req.user,"tasks",id);
  allow(req,['ADMIN','OPERATOR']);const v=parse(z.object({notBefore:z.string().datetime(),windowEnd:z.string().datetime()}).strict(),body);
  if(new Date(v.windowEnd)<=new Date(v.notBefore)||new Date(v.windowEnd)<=new Date())throw new BadRequestException('执行窗口无效');
  await assertLinks(this.p.db,req.user,v);
  return this.p.db.$transaction(async tx=>{const c=await tx.task.updateMany({where:{id,status:{in:['PENDING','APPROVED']}},data:{notBefore:new Date(v.notBefore),windowEnd:new Date(v.windowEnd),status:'PENDING',approvedBy:null}});if(!c.count)throw new ConflictException('执行后不能修改窗口');await this.p.audit(tx,req.user.email,'RESCHEDULE','tasks',id,v);return tx.task.findUnique({where:{id}});});
 }
 @Get('export') async export(@Query() query:any,@Req() req:any){
  const v=parse(pageInput.omit({page:true,pageSize:true}).extend({resource:z.enum(['assets','findings','incidents','rules','tasks','sites','discoveries'])}),query);
  const items:any[]=[];let total=0;for(let page=1;page<=100;page++){const result=v.resource==='discoveries'?await this.p.discoveries({...v,page,pageSize:100},req.user):await this.p.list(v.resource,{...v,page,pageSize:100},req.user);total=result.total;for(const item of result.items){if(v.resource==='tasks'){const {parameters,result:execution,...rest}=item;items.push(rest);}else items.push(item);}if(items.length>=total)break;}
  await this.p.db.audit.create({data:{actor:req.user.email,action:'EXPORT',resource:v.resource,detail:{filters:v,count:items.length,total}}});return {items,total,truncated:items.length<total,filters:v,generatedAt:new Date().toISOString()};
 }
 @Get('batches') async batches(@Req() req:any){return {items:await this.p.db.taskBatch.findMany({where:await resourceWhere(this.p.db,req.user,'batches'),orderBy:{createdAt:'desc'},take:100})};}
 @Post('batches') async batch(@Body() body:unknown,@Req() req:any){
  allow(req,['ADMIN','OPERATOR']);const v=parse(z.object({title:text,taskIds:z.array(z.string().uuid()).min(1).max(100),stopOnFailure:z.boolean().default(true)}).strict(),body);
  await assertLinks(this.p.db,req.user,v);
  return this.p.db.$transaction(async tx=>{await tx.$queryRaw`SELECT pg_advisory_xact_lock(hashtext('selfguard-batch-create'))::text`;if(await tx.task.count({where:{id:{in:v.taskIds},status:'PENDING',batchId:null}})!==new Set(v.taskIds).size)throw new ConflictException('仅未分组待审批任务可以组成批次');const b=await tx.taskBatch.create({data:{title:v.title,stopOnFailure:v.stopOnFailure,createdBy:req.user.email,status:'RUNNING'}});const grouped=await tx.task.updateMany({where:{id:{in:v.taskIds},status:'PENDING',batchId:null},data:{batchId:b.id}});if(grouped.count!==new Set(v.taskIds).size)throw new ConflictException('任务审批或分组状态已变化');await this.p.audit(tx,req.user.email,'CREATE','batches',b.id,{count:v.taskIds.length});return b;});
 }
 @Post('batches/:id/stop') async stop(@Param('id') id:string,@Req() req:any){allow(req,['ADMIN','OPERATOR']);await assertScope(this.p.db,req.user,'batches',id);return this.p.db.$transaction(async tx=>{await tx.taskBatch.update({where:{id},data:{status:'STOPPED'}});await tx.task.updateMany({where:{batchId:id,status:{in:['PENDING','APPROVED']}},data:{status:'CANCELLED',reason:'批次停止；不撤销已经完成的变更'}});await this.p.audit(tx,req.user.email,'STOP','batches',id);return {ok:true};});}
}
