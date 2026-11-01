import {BadRequestException,Body,ConflictException,Controller,Get,Inject,Injectable,NotFoundException,Param,Patch,Post,Req,UseGuards} from '@nestjs/common';
import {X509Certificate} from 'node:crypto';import {createSecureContext} from 'node:tls';import{isIP}from'node:net';import{z}from'zod';
import{Db}from'./db';import{Platform}from'./platform';import{AuthGuard,allow,component}from'./auth';import{parse}from'./validation';import{seal,unseal}from'./maintenance';
const hostname=z.string().trim().toLowerCase().max(253).regex(/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/).refine(v=>!isIP(v),'需要 DNS 域名');
const pemInput=z.object({certificate:z.string().min(1).max(65536),privateKey:z.string().min(1).max(16384)}).strict();
export function validateCertificate(host:string,certificate:string,privateKey:string){
 let leaf:X509Certificate;try{createSecureContext({cert:certificate,key:privateKey,minVersion:'TLSv1.2'});leaf=new X509Certificate(certificate);}catch{throw new BadRequestException('证书或私钥 PEM 无效，或私钥与证书不匹配');}
 if(!leaf.checkHost(host,{subject:'never'}))throw new BadRequestException('证书不匹配目标域名');
 const notBefore=new Date(leaf.validFrom),notAfter=new Date(leaf.validTo),now=new Date();
 if(!(notBefore<=now&&notAfter>now))throw new BadRequestException('证书已过期或尚未生效');
 return{notAfter,notBefore,fingerprint:leaf.fingerprint256,issuer:leaf.issuer,subject:leaf.subject};
}
function metadata(row:any){const leaf=new X509Certificate(row.certificate);return{id:row.id,hostname:row.hostname,notAfter:row.notAfter,notBefore:new Date(leaf.validFrom),fingerprint:leaf.fingerprint256,issuer:leaf.issuer,version:row.version,enabled:row.enabled,createdAt:row.createdAt,updatedAt:row.updatedAt};}
@Injectable()
export class CertificateService{
 constructor(@Inject(Db)readonly db:Db,@Inject(Platform)readonly p:Platform){}
 async list(){return{items:(await this.db.siteCertificate.findMany({orderBy:{hostname:'asc'}})).map(metadata)};}
 async upload(body:unknown,actor:string){const v=parse(pemInput.extend({hostname}),body);const checked=validateCertificate(v.hostname,v.certificate,v.privateKey);const keyCiphertext=seal(v.privateKey);
 return this.db.$transaction(async tx=>{await tx.$queryRaw`SELECT pg_advisory_xact_lock(hashtext(${'certificate-inventory'}))::text`;if(await tx.siteCertificate.findUnique({where:{hostname:v.hostname}}))throw new ConflictException('域名已有证书，请使用轮换');const count=await tx.siteCertificate.count();if(count>=200)throw new BadRequestException('集中证书管理最多支持200个域名');const row=await tx.siteCertificate.create({data:{hostname:v.hostname,certificate:v.certificate,keyCiphertext,notAfter:checked.notAfter}});await this.p.audit(tx,actor,'CERTIFICATE_UPLOAD','certificates',row.id,{hostname:row.hostname,version:row.version,fingerprint:checked.fingerprint,notAfter:checked.notAfter.toISOString()});return metadata(row);});}
 async rotate(id:string,body:unknown,actor:string){const v=parse(pemInput,body);return this.db.$transaction(async tx=>{const old=await tx.siteCertificate.findUnique({where:{id}});if(!old)throw new NotFoundException('证书不存在');const checked=validateCertificate(old.hostname,v.certificate,v.privateKey);const row=await tx.siteCertificate.update({where:{id},data:{certificate:v.certificate,keyCiphertext:seal(v.privateKey),notAfter:checked.notAfter,version:{increment:1}}});await this.p.audit(tx,actor,'CERTIFICATE_ROTATE','certificates',id,{hostname:row.hostname,version:row.version,fingerprint:checked.fingerprint,notAfter:checked.notAfter.toISOString()});return metadata(row);});}
 async status(id:string,body:unknown,actor:string){const v=parse(z.object({enabled:z.boolean()}).strict(),body);return this.db.$transaction(async tx=>{const old=await tx.siteCertificate.findUnique({where:{id}});if(!old)throw new NotFoundException('证书不存在');if(v.enabled)validateCertificate(old.hostname,old.certificate,unseal(old.keyCiphertext));const row=await tx.siteCertificate.update({where:{id},data:{enabled:v.enabled,version:{increment:1}}});await this.p.audit(tx,actor,v.enabled?'CERTIFICATE_ENABLE':'CERTIFICATE_DISABLE','certificates',id,{hostname:row.hostname,version:row.version});return metadata(row);});}
 async componentCertificates(){const rows=await this.db.siteCertificate.findMany({where:{enabled:true,notAfter:{gt:new Date()}},orderBy:{hostname:'asc'}});return{items:rows.map(row=>({hostname:row.hostname,certificate:row.certificate,privateKey:unseal(row.keyCiphertext),version:row.version})),generatedAt:new Date().toISOString()};}
}
@Controller('certificates') @UseGuards(AuthGuard)
export class CertificateController{
 constructor(@Inject(CertificateService)readonly service:CertificateService){}
 @Get()async list(@Req()req:any){allow(req,['ADMIN']);return this.service.list();}
 @Post()async upload(@Req()req:any,@Body()body:unknown){allow(req,['ADMIN']);return this.service.upload(body,req.user.email);}
 @Post(':id/rotate')async rotate(@Req()req:any,@Param('id')id:string,@Body()body:unknown){allow(req,['ADMIN']);return this.service.rotate(id,body,req.user.email);}
 @Patch(':id/status')async disable(@Req()req:any,@Param('id')id:string,@Body()body:unknown){allow(req,['ADMIN']);return this.service.status(id,body,req.user.email);}
}
@Controller('waf')
export class WafCertificatesController{
 constructor(@Inject(CertificateService)readonly service:CertificateService){}
 @Get('certificates')async list(@Req()req:any){component(req,'WAF_TOKEN');return this.service.componentCertificates();}
}
