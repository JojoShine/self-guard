import {Body,Controller,Inject,Injectable,Post,Req,UnauthorizedException,UseGuards} from '@nestjs/common';
import {Prisma} from '@prisma/client';
import {z} from 'zod';
import {Db} from './db';
import {AUDIT_DB} from './audit-db';
import {AuthGuard,allow,bearer} from './auth';
import {Platform} from './platform';
import {hashToken} from './security';
import {parse} from './validation';
import {assertEvidence} from './scope';
import {assertInstanceScope} from './database-instances';
import {databaseEventInput,SecurityRequest} from './database-contract';
import {ingestDatabaseEvents} from './database-audit';
const input=z.object({events:z.array(databaseEventInput).min(1).max(100)}).strict();
type AgentRequest={headers:{authorization?:string}};
@Injectable()
export class AuditAuthGuard extends AuthGuard{
 constructor(@Inject(AUDIT_DB)db:Db){super(db);}
}
@Controller('agent')
export class AgentDatabaseAuditController{
 private readonly platform:Platform;
 constructor(@Inject(AUDIT_DB)private readonly db:Db){this.platform=new Platform(db);}
 @Post('database-audit')async databaseAudit(@Req()req:AgentRequest,@Body()body:unknown){
  const token=bearer(req);if(!token)throw new UnauthorizedException();
  const tokenHash=hashToken(token),asset=await this.db.asset.findUnique({where:{tokenHash}});
  if(!asset||asset.archivedAt)throw new UnauthorizedException('Agent 身份无效');
  const value=parse(input,body);
  return this.db.$transaction(async(tx:Prisma.TransactionClient)=>{
   await tx.$queryRaw`SELECT id FROM "Asset" WHERE id=${asset.id} FOR UPDATE`;
   const current=await tx.asset.findUnique({where:{id:asset.id}});
   if(!current||current.archivedAt||current.tokenHash!==tokenHash)throw new UnauthorizedException('Agent 凭据已撤销或身份无效');
   return ingestDatabaseEvents(tx,this.platform,value.events,asset.id);
  },{timeout:30000});
 }
}
@Controller('data-security') @UseGuards(AuditAuthGuard)
export class DatabaseAuditImportController{
 private readonly platform:Platform;
 constructor(@Inject(AUDIT_DB)private readonly db:Db){this.platform=new Platform(db);}
 @Post('events')async importEvents(@Req()req:SecurityRequest,@Body()body:unknown){
  allow(req,['ADMIN','ANALYST']);assertEvidence(req.user);const value=parse(input,body);
  return this.db.$transaction(async tx=>{
   for(const event of value.events)await assertInstanceScope(tx,req.user,event.instanceId);
   const result=await ingestDatabaseEvents(tx,this.platform,value.events);
   await tx.audit.create({data:{actor:req.user.email,action:'DATABASE_AUDIT_IMPORT',resource:'database-audit',detail:result}});
   return result;
  },{timeout:30000});
 }
}
