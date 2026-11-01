import {Body,Controller,Get,HttpException,Inject,Patch,Req,UseGuards} from '@nestjs/common';
import {Prisma} from '@prisma/client';import {z} from 'zod';import {Db} from './db';import {AuthGuard,allow} from './auth';import {parse} from './validation';
import {intelligenceArtifactUsage,intelligenceArtifactQuota} from './intelligence-artifacts';
type Tx=Prisma.TransactionClient;
export const storageInput=z.object({intelligenceArtifactQuotaGiB:z.number().int().min(1).max(1024).optional(),automaticCleanup:z.boolean().optional(),telemetryLimit:z.number().int().min(100).max(10000000).optional(),wafEventLimit:z.number().int().min(100).max(10000000).optional(),accessLimit:z.number().int().min(100).max(10000000).optional(),telemetryDays:z.number().int().min(1).max(3650).optional(),accessDays:z.number().int().min(1).max(3650).optional(),assetChangeDays:z.number().int().min(30).max(3650).optional()}).strict();
const defaults={intelligenceArtifactQuotaGiB:5,automaticCleanup:false,telemetryLimit:1000000,wafEventLimit:1000000,accessLimit:100000,telemetryDays:30,accessDays:30,assetChangeDays:365};
async function policy(tx:Tx){return {...defaults,...parse(storageInput,(await tx.setting.findUnique({where:{key:'storage-policy'}}))?.value||{})};}
export async function telemetryRetentionDays(tx:Tx){return (await policy(tx)).telemetryDays;}
// Acquire before inserting and retain the lock through admission and commit.
export async function lockEventStorage(tx:Tx){await tx.$queryRaw`SELECT pg_advisory_xact_lock(hashtext('selfguard-event-storage'))::text`;}
export async function assertEventCapacity(tx:Tx,kind:'telemetry'|'wafEvents'|'access',added:number){
 if(!added)return;await lockEventStorage(tx);const p=await policy(tx);
 const count=kind==='telemetry'?await tx.telemetryEvent.count():kind==='wafEvents'?await tx.wafEvent.count():await tx.wafAccess.count();
 const limit=kind==='telemetry'?p.telemetryLimit:kind==='wafEvents'?p.wafEventLimit:p.accessLimit;
 if(count>limit)throw new HttpException('事件存储上限已达到；请清理到期记录或提高上限，组件将保留未确认队列',507);
}
export async function sweepStorage(db:Db){return db.$transaction(async tx=>{
 await lockEventStorage(tx);const p=await policy(tx);if(!p.automaticCleanup)return null;
 const last=await tx.setting.findUnique({where:{key:'storage-cleanup:last'}}),now=new Date();
 if(last&&now.getTime()-Date.parse(String((last.value as any)?.at))<3600000)return null;
 const retention=(await tx.setting.findUnique({where:{key:'retention'}}))?.value as any||{};
 const cutoff=(days:number)=>new Date(now.getTime()-days*86400000);
 const result={telemetry:(await tx.telemetryEvent.deleteMany({where:{OR:[{expiresAt:{lte:now}},{receivedAt:{lt:cutoff(p.telemetryDays)}}]}})).count,access:(await tx.wafAccess.deleteMany({where:{timestamp:{lt:cutoff(p.accessDays)}}})).count,assetChanges:(await tx.assetChange.deleteMany({where:{createdAt:{lt:cutoff(p.assetChangeDays)}}})).count,audit:(await tx.audit.deleteMany({where:{createdAt:{lt:cutoff(Math.max(30,retention.auditDays||365))}}})).count,wafEvents:(await tx.wafEvent.deleteMany({where:{createdAt:{lt:cutoff(retention.wafEventDays||90)}}})).count,evaluations:(await tx.evaluation.deleteMany({where:{createdAt:{lt:cutoff(retention.evaluationDays||90)}}})).count,notifications:(await tx.notification.deleteMany({where:{createdAt:{lt:cutoff(retention.notificationDays||90)}}})).count};
 const value={at:now.toISOString(),deleted:result};await tx.setting.upsert({where:{key:'storage-cleanup:last'},create:{key:'storage-cleanup:last',value},update:{value}});await tx.audit.create({data:{actor:'scheduler',action:'RETENTION_CLEANUP',resource:'storage',detail:value}});return result;
 },{timeout:30000});}
@Controller('storage') @UseGuards(AuthGuard)
export class StorageController{
 constructor(@Inject(Db) private db:Db){}
 @Get() async status(@Req()req:any){allow(req,['ADMIN']);const [p,telemetry,wafEvents,access,assetChanges,size,last]=await Promise.all([policy(this.db),this.db.telemetryEvent.count(),this.db.wafEvent.count(),this.db.wafAccess.count(),this.db.assetChange.count(),this.db.$queryRaw<Array<{bytes:bigint}>>`SELECT pg_database_size(current_database()) AS bytes`,this.db.setting.findUnique({where:{key:'storage-cleanup:last'}})]);const [artifactUsage,reserved,limitBytes]=await Promise.all([intelligenceArtifactUsage(),this.db.vulnerabilitySnapshot.aggregate({where:{status:'STAGING'},_sum:{reservedArtifactBytes:true}}),intelligenceArtifactQuota(this.db)]);return{intelligenceArtifacts:{...artifactUsage,reservedBytes:reserved._sum.reservedArtifactBytes||0,limitBytes},policy:p,counts:{telemetry,wafEvents,access,assetChanges},databaseBytes:Number(size[0].bytes),lastCleanup:last?.value||null,basis:'行数上限作用于遥测、WAF安全事件和访问快照；数据库字节数包含索引与空闲页，不是磁盘硬配额',checkedAt:new Date().toISOString()};}
 @Patch() async configure(@Req()req:any,@Body()body:unknown){allow(req,['ADMIN']);const v=parse(storageInput,body);return this.db.$transaction(async tx=>{await lockEventStorage(tx);const value={...await policy(tx),...v};await tx.setting.upsert({where:{key:'storage-policy'},create:{key:'storage-policy',value},update:{value}});await tx.audit.create({data:{actor:req.user.email,action:'STORAGE_POLICY',resource:'settings',detail:value}});return value;});}
}
