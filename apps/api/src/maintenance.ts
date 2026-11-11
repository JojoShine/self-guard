import {assertScope} from "./scope";
import {Controller,Get,Post,Patch,Req,Body,Inject,UseGuards,Injectable,OnModuleInit,OnModuleDestroy,BadRequestException} from '@nestjs/common';
import {Db} from './db';import {AuthGuard,allow} from './auth';import {parse} from './validation';import {z} from 'zod';
import {createCipheriv,createDecipheriv,randomBytes,createHmac} from 'node:crypto';import {lookup} from 'node:dns/promises';import https from 'node:https';import {publicAddress} from './advisories';
function encryptionKey(){const k=process.env.DATA_ENCRYPTION_KEY;if(!k||!/^[a-f0-9]{64}$/i.test(k))throw new BadRequestException('部署者需要配置32字节DATA_ENCRYPTION_KEY');return Buffer.from(k,'hex');}
export function seal(value:string){const iv=randomBytes(12),cipher=createCipheriv('aes-256-gcm',encryptionKey(),iv);return Buffer.concat([iv,cipher.update(value),cipher.final(),cipher.getAuthTag()]).toString('base64');}
export function unseal(value:string){const b=Buffer.from(value,'base64');const keys=[encryptionKey()];const previous=process.env.DATA_ENCRYPTION_PREVIOUS_KEY;if(previous&&/^[a-f0-9]{64}$/i.test(previous))keys.push(Buffer.from(previous,'hex'));
 for(const key of keys){try{const d=createDecipheriv('aes-256-gcm',key,b.subarray(0,12));d.setAuthTag(b.subarray(-16));return Buffer.concat([d.update(b.subarray(12,-16)),d.final()]).toString()}catch{}}
 throw new BadRequestException('密钥不能解密该记录');
}
export function webhookUrl(raw:string){const u=new URL(raw);if(u.protocol!=='https:'||u.username||u.password||u.hash||u.port&&u.port!=='443')throw new BadRequestException('仅支持无凭据的HTTPS webhook');return u;}
export async function deliverWebhook(raw:string,secret:string,payload:unknown,id:string){
 const u=webhookUrl(raw);const addresses=await lookup(u.hostname,{all:true});if(!addresses.length||addresses.some(a=>!publicAddress(a.address)))throw new Error('Webhook地址不允许');const addr=addresses[0];const body=JSON.stringify(payload);if(Buffer.byteLength(body)>65536)throw new Error('Webhook payload too large');
 await new Promise<void>((resolve,reject)=>{const req=https.request(u,{method:'POST',lookup:((_host:any,_opts:any,cb:any)=>_opts?.all?cb(null,[addr]):cb(null,addr.address,addr.family)) as any,headers:{'Content-Type':'application/json','Content-Length':Buffer.byteLength(body),'X-SelfGuard-Delivery':id,'X-SelfGuard-Signature':createHmac('sha256',secret).update(body).digest('hex')}},res=>{res.resume();res.on('end',()=>res.statusCode&&res.statusCode>=200&&res.statusCode<300?resolve():reject(new Error('Webhook未确认接收')))});const timer=setTimeout(()=>req.destroy(new Error('Webhook超时')),10000);req.on('close',()=>clearTimeout(timer));req.on('error',reject);req.end(body)});
}
@Injectable()
export class DeliveryService implements OnModuleInit,OnModuleDestroy {
 private timer?:ReturnType<typeof setInterval>;private busy=false;
 constructor(@Inject(Db) private db:Db){}
 onModuleInit(){this.timer=setInterval(()=>void this.tick(),30000);this.timer.unref();}
 onModuleDestroy(){if(this.timer)clearInterval(this.timer);}
 async tick(sender=deliverWebhook){if(this.busy)return;this.busy=true;try{
  await this.db.delivery.updateMany({where:{status:'SENDING',updatedAt:{lt:new Date(Date.now()-60000)}},data:{status:'PENDING'}});
  const configs=await this.db.setting.findMany({where:{key:{startsWith:'webhook:'}}});
  for(const c of configs){const config=c.value as any;if(!config.enabled)continue;const userId=c.key.slice(8);const u=await this.db.user.findUnique({where:{id:userId}});if(!u||u.disabled)continue;
   const candidates=await this.db.notification.findMany({where:{userId,inAppOnly:false,createdAt:{gte:new Date(Date.now()-86400000)}},orderBy:{createdAt:'asc'},take:1000});
   const notes=[];for(const n of candidates){try{if(n.resourceId)await assertScope(this.db,u,n.resource,n.resourceId);notes.push(n)}catch{await this.db.delivery.updateMany({where:{id:n.id,status:{in:['PENDING','SENDING']}},data:{status:'CANCELLED',lastError:'资源授权已变化'}})}}
   await this.db.delivery.createMany({data:notes.map(n=>({id:n.id,userId,notificationId:n.id})),skipDuplicates:true});
   const due=await this.db.delivery.findMany({where:{userId,status:'PENDING',availableAt:{lte:new Date()}},orderBy:{createdAt:'asc'},take:20});
   for(const job of due){const claimed=await this.db.delivery.updateMany({where:{id:job.id,status:'PENDING'},data:{status:'SENDING',attempts:{increment:1}}});if(!claimed.count)continue;
    const n=await this.db.notification.findUnique({where:{id:job.notificationId}});if(!n||n.inAppOnly){await this.db.delivery.update({where:{id:job.id},data:{status:'CANCELLED',lastError:n?.inAppOnly?'仅站内提醒':null}});continue;}
    try{const currentUser=await this.db.user.findUnique({where:{id:userId}});if(!currentUser||currentUser.disabled)throw new Error('disabled');if(n.resourceId)await assertScope(this.db,currentUser,n.resource,n.resourceId);}catch{await this.db.delivery.update({where:{id:job.id},data:{status:'CANCELLED',lastError:'资源授权已变化'}});continue;}
    try{await sender(unseal(config.endpoint),unseal(config.secret),{id:n.id,title:n.title,resource:n.resource,resourceId:n.resourceId,createdAt:n.createdAt},job.id);await this.db.delivery.update({where:{id:job.id},data:{status:'DELIVERED',lastError:null}})}catch{await this.db.delivery.update({where:{id:job.id},data:{status:job.attempts>=4?'FAILED':'PENDING',availableAt:new Date(Date.now()+Math.min(3600,30*2**job.attempts)*1000),lastError:'发送失败，可检查接收端后重试；密钥与URL不会写入日志'}})}
   }
  }
 }catch{/* subsequent ticks retry without exposing credentials */}finally{this.busy=false}}
}
@Controller('maintenance') @UseGuards(AuthGuard)
export class MaintenanceController {
 constructor(@Inject(Db) private db:Db){}
 @Get('backup') async backup(@Req() req:any){allow(req,['ADMIN']);return {policy:(await this.db.setting.findUnique({where:{key:'backup:policy'}}))?.value||{enabled:false,intervalHours:24,keepCount:7},last:(await this.db.setting.findUnique({where:{key:'backup:last'}}))?.value||null};}
 @Patch('backup') async saveBackup(@Req() req:any,@Body() body:unknown){allow(req,['ADMIN']);const value=parse(z.object({enabled:z.boolean(),intervalHours:z.number().int().min(1).max(168),keepCount:z.number().int().min(1).max(30)}).strict(),body);await this.db.$transaction(async tx=>{await tx.setting.upsert({where:{key:'backup:policy'},create:{key:'backup:policy',value},update:{value}});await tx.audit.create({data:{actor:req.user.email,action:'BACKUP_POLICY',resource:'settings',detail:value}})});return this.backup(req);}
 @Get('webhook') async webhook(@Req() req:any){const c=await this.db.setting.findUnique({where:{key:'webhook:'+req.user.id}});const v=c?.value as any;return {enabled:!!v?.enabled,configured:!!v?.endpoint,secretConfigured:!!v?.secret};}
 @Patch('webhook') async save(@Req() req:any,@Body() body:unknown){const v=parse(z.object({enabled:z.boolean(),url:z.string().url().max(2000).optional(),secret:z.string().min(16).max(500).optional()}).strict(),body);const key='webhook:'+req.user.id;const previous=(await this.db.setting.findUnique({where:{key}}))?.value as any;const value:any={enabled:v.enabled,endpoint:previous?.endpoint,secret:previous?.secret};if(v.url){webhookUrl(v.url);value.endpoint=seal(v.url)}if(v.secret)value.secret=seal(v.secret);if(v.enabled&&(!value.endpoint||!value.secret))throw new BadRequestException('启用前需要配置URL和签名密钥');await this.db.$transaction(async tx=>{await tx.setting.upsert({where:{key},create:{key,value},update:{value}});await tx.audit.create({data:{actor:req.user.email,action:'WEBHOOK_SETTINGS',resource:'settings',detail:{enabled:v.enabled}}})});return this.webhook(req);}
 @Get('deliveries') async deliveries(@Req() req:any){return {items:await this.db.delivery.findMany({where:req.user.role==='ADMIN'?{}:{userId:req.user.id},orderBy:{createdAt:'desc'},take:100})};}
 @Post('deliveries/retry') async retry(@Req() req:any,@Body() body:unknown){const v=parse(z.object({id:z.string().min(1).max(100)}).strict(),body);const count=await this.db.delivery.updateMany({where:{id:v.id,userId:req.user.id,status:'FAILED'},data:{status:'PENDING',attempts:0,availableAt:new Date()}});return {updated:count.count};}
}
@Controller('health')
export class ReadinessController {
 constructor(@Inject(Db) private db:Db){}
 @Get('ready') async ready(){await this.db.$queryRaw`SELECT 1`;return {ready:true};}
}
