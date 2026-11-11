import {Body,Controller,Get,Inject,Param,Post,Req,UseGuards,BadRequestException,ConflictException,NotFoundException} from '@nestjs/common';
import {z} from 'zod';
import {Prisma} from '@prisma/client';
import {Db} from './db';
import {AuthGuard,allow} from './auth';
import {assertEvidence,assertScope,resourceWhere} from './scope';
import {parse} from './validation';
import type {SecurityRequest} from './database-contract';

const triageInput=z.object({conclusion:z.enum(['DUPLICATE','INSUFFICIENT_EVIDENCE','NONE']),duplicateOfId:z.string().uuid().optional(),reason:z.string().trim().min(5).max(4000),expectedUpdatedAt:z.string().datetime()}).strict().refine(v=>v.conclusion==='DUPLICATE'?!!v.duplicateOfId:!v.duplicateOfId,'仅重复结论需要关联原问题');

async function view(tx:Prisma.TransactionClient,user:SecurityRequest['user'],id:string){
 await assertScope(tx,user,'findings',id);
 const finding=await tx.finding.findUnique({where:{id},select:{id:true,status:true,updatedAt:true}});if(!finding)throw new NotFoundException();
 const row=await tx.findingTriage.findUnique({where:{findingId:id}});if(!row)return{finding,triage:null};
 const {duplicateOfId,...metadata}=row;
 const duplicate=duplicateOfId?await tx.finding.findFirst({where:{AND:[{id:duplicateOfId},await resourceWhere(tx,user,'findings')]},select:{id:true,title:true}}):null;
 return{finding,triage:{...metadata,duplicate,duplicateUnavailable:!!duplicateOfId&&!duplicate}};
}

@Controller('findings') @UseGuards(AuthGuard)
export class FindingTriageController{
 constructor(@Inject(Db)private db:Db){}
 @Get(':id/triage') async read(@Req()req:SecurityRequest,@Param('id')id:string){assertEvidence(req.user);return this.db.$transaction(tx=>view(tx,req.user,id));}
 @Post(':id/triage') async save(@Req()req:SecurityRequest,@Param('id')id:string,@Body()body:unknown){
  allow(req,['ADMIN','ANALYST']);assertEvidence(req.user);const v=parse(triageInput,body);
  return this.db.$transaction(async tx=>{
   // Serializes relationship changes so concurrent A→B and B→A cannot create a cycle.
   await tx.$queryRaw`SELECT pg_advisory_xact_lock(hashtext(current_schema()),hashtext('finding-triage'))::text`;
   await assertScope(tx,req.user,'findings',id);const source=await tx.finding.findUniqueOrThrow({where:{id}});
   if(!['RISK','ALERT'].includes(source.kind))throw new BadRequestException('仅风险或告警支持核查结论');
   if(source.updatedAt.getTime()!==Date.parse(v.expectedUpdatedAt))throw new ConflictException('问题已更新，请刷新后重新核查');
   if(v.duplicateOfId){
    if(v.duplicateOfId===id)throw new BadRequestException('不能关联问题自身');
    await assertScope(tx,req.user,'findings',v.duplicateOfId);const target=await tx.finding.findUniqueOrThrow({where:{id:v.duplicateOfId}});
    if(target.kind!==source.kind)throw new BadRequestException('重复问题需要关联同类型的原问题');
    if(await tx.findingTriage.count({where:{OR:[{findingId:v.duplicateOfId,conclusion:'DUPLICATE'},{duplicateOfId:id}]}}))throw new BadRequestException('不能形成链式关联；请直接关联原问题，有重复项指向的原问题不能再标为重复');
   }
   const before=await tx.findingTriage.findUnique({where:{findingId:id}});
   const changed=await tx.finding.updateMany({where:{id,updatedAt:source.updatedAt},data:{updatedAt:new Date(Math.max(Date.now(),source.updatedAt.getTime()+1))}});if(!changed.count)throw new ConflictException('问题已更新，请刷新后重新核查');
   if(v.conclusion==='NONE')await tx.findingTriage.deleteMany({where:{findingId:id}});
   else{const data={conclusion:v.conclusion,duplicateOfId:v.duplicateOfId||null,reason:v.reason,updatedBy:req.user.email};await tx.findingTriage.upsert({where:{findingId:id},create:{findingId:id,...data},update:data});}
   await tx.audit.create({data:{actor:req.user.email,action:'FINDING_TRIAGE',resource:'findings',resourceId:id,detail:{before,after:v}}});
   return view(tx,req.user,id);
  });
 }
}
