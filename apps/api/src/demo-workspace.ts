import {BadRequestException,ConflictException,Controller,ForbiddenException,Get,GoneException,Header,Inject,Injectable,Post,Body,Req,UseGuards} from '@nestjs/common';
import {randomUUID} from 'node:crypto';
import {z} from 'zod';
import {AuthGuard,bearer} from './auth';
import {Db} from './db';
import {DEMO_EMAIL} from './public-demo';
import {hashToken} from './security';
import {parse} from './validation';
import {parseCapturedSql} from './traffic-sql';
const prefix='demo-workspace:',ttl=8*3600000;
const id=z.string().uuid(),name=z.string().trim().min(1).max(80),revision=z.number().int().min(0).max(Number.MAX_SAFE_INTEGER),profile=z.enum(['OUTDATED','CURRENT']),findingStatus=z.enum(['OPEN','CONFIRMED','RESOLVED']);
export const demoCommandInput=z.discriminatedUnion('action',[
 z.object({action:z.literal('ADD_ASSET'),revision,name,profile}).strict(),
 z.object({action:z.literal('REMOVE_ASSET'),revision,id}).strict(),
 z.object({action:z.literal('CREATE_SCAN'),revision,name,assetIds:z.array(id).min(1).max(20).refine(ids=>new Set(ids).size===ids.length)}).strict(),
 z.object({action:z.literal('EXECUTE_SCAN'),revision,id}).strict(),
 z.object({action:z.literal('UPDATE_FINDING'),revision,id,status:findingStatus}).strict(),
 z.object({action:z.literal('PARSE_SQL'),revision,sample:z.enum(['SIMPLE','PREPARED','TLS'])}).strict(),
 z.object({action:z.literal('RESET'),revision}).strict(),
]);
const workspaceInput=z.object({revision,expiresAt:z.number().int().positive(),assets:z.array(z.object({id,name,profile}).strict()).max(20),scans:z.array(z.object({id,name,assetIds:z.array(id).max(20),status:z.enum(['READY','DONE']),findingIds:z.array(id).max(40)}).strict()).max(10),findings:z.array(z.object({id,scanId:id,assetId:id,title:z.string().max(160),summary:z.string().max(500),status:findingStatus}).strict()).max(40),sqlSamples:z.array(z.object({id,label:z.string().max(80),state:z.enum(['EXTRACTED','PARTIAL','UNAVAILABLE','UNSUPPORTED']),statements:z.array(z.object({sql:z.string().max(32768),stage:z.enum(['QUERY','PREPARE','EXECUTE'])}).strict()).max(100),reasons:z.array(z.string().max(64)).max(20)}).strict()).max(5)}).strict();
export type DemoWorkspace=z.infer<typeof workspaceInput>;
type DemoUser={email:string};
export function demoWorkspaceKey(user:DemoUser,token:string){if(user.email!==DEMO_EMAIL||!token)throw new ForbiddenException('仅供已登录的体验账号使用');return prefix+hashToken(token);}
export function newDemoWorkspace(now=Date.now()):DemoWorkspace{return{revision:0,expiresAt:now+ttl,assets:[{id:randomUUID(),name:'版本待更新的样例主机',profile:'OUTDATED'},{id:randomUUID(),name:'已更新的样例主机',profile:'CURRENT'}],scans:[],findings:[],sqlSamples:[]};}
function frame(kind:string,body:Buffer|string){const data=Buffer.isBuffer(body)?body:Buffer.from(body),out=Buffer.alloc(data.length+5);out[0]=kind.charCodeAt(0);out.writeUInt32BE(data.length+4,1);data.copy(out,5);return out;}
function sqlSample(sample:'SIMPLE'|'PREPARED'|'TLS'){
 const request=sample==='TLS'?Buffer.from([0x16,3,3,0,5]):sample==='SIMPLE'?frame('Q','SELECT 42 AS demo_value\0'):Buffer.concat([frame('P',Buffer.concat([Buffer.from('s\0SELECT $1::integer AS demo_value\0'),Buffer.alloc(2)])),frame('B',Buffer.concat([Buffer.from('p\0s\0'),Buffer.from('000000010000000234320000','hex')])),frame('E',Buffer.concat([Buffer.from('p\0'),Buffer.alloc(4)]))]);
 return{id:randomUUID(),label:({SIMPLE:'普通查询报文样例',PREPARED:'预编译执行报文样例',TLS:'TLS加密报文样例'})[sample],...parseCapturedSql('POSTGRESQL',request)};
}
export function applyDemoCommand(previous:DemoWorkspace,body:unknown,now=Date.now()):DemoWorkspace{
 const command=parse(demoCommandInput,body);
 if(previous.expiresAt<=now)throw new GoneException('体验空间已到期，请刷新');
 if(command.revision!==previous.revision)throw new ConflictException('体验内容已变化，请刷新后重试');
 const state=workspaceInput.parse(structuredClone(previous));
 if(command.action==='RESET')return{...newDemoWorkspace(now),revision:state.revision+1};
 if(command.action==='ADD_ASSET'){
  if(state.assets.length>=20)throw new BadRequestException('最多保留20个演示资产，请删除或重置');
  state.assets.push({id:randomUUID(),name:command.name,profile:command.profile});
 }else if(command.action==='REMOVE_ASSET'){
  if(!state.assets.some(asset=>asset.id===command.id))throw new BadRequestException('当前体验资产不存在');
  if(state.scans.some(scan=>scan.assetIds.includes(command.id)))throw new ConflictException('资产已有体验任务，请重置空间后再删除');
  state.assets=state.assets.filter(asset=>asset.id!==command.id);
 }else if(command.action==='CREATE_SCAN'){
  if(state.scans.length>=10)throw new BadRequestException('最多保留10个体验任务，请重置后继续');
  if(command.assetIds.some(assetId=>!state.assets.some(asset=>asset.id===assetId)))throw new BadRequestException('只能选择当前体验空间的资产');
  state.scans.push({id:randomUUID(),name:command.name,assetIds:command.assetIds,status:'READY',findingIds:[]});
 }else if(command.action==='EXECUTE_SCAN'){
  const scan=state.scans.find(item=>item.id===command.id);if(!scan)throw new BadRequestException('当前体验任务不存在');
  if(scan.status==='READY'){
   const affected=state.assets.filter(asset=>scan.assetIds.includes(asset.id)&&asset.profile==='OUTDATED');
   if(state.findings.length+affected.length>40)throw new BadRequestException('最多保留40个体验问题，请重置后继续');
   for(const asset of affected){const finding={id:randomUUID(),scanId:scan.id,assetId:asset.id,title:'样例组件版本低于演示基线',summary:'内置样例规则：演示版本1.0低于基线2.0。此结果只用于体验流程，不是实际CVE判断或真实网络扫描结果。',status:'OPEN' as const};state.findings.push(finding);scan.findingIds.push(finding.id);}
   scan.status='DONE';
  }
 }else if(command.action==='UPDATE_FINDING'){
  const finding=state.findings.find(item=>item.id===command.id);if(!finding)throw new BadRequestException('当前体验问题不存在');finding.status=command.status;
 }else{
  if(state.sqlSamples.length>=5)state.sqlSamples.shift();state.sqlSamples.push(sqlSample(command.sample));
 }
 state.revision++;return workspaceInput.parse(state);
}
@Injectable()
export class DemoWorkspaceService{
 constructor(@Inject(Db)private db:Db){}
 read(user:DemoUser,token:string){return this.access(user,token);}
 command(user:DemoUser,token:string,body:unknown){return this.access(user,token,parse(demoCommandInput,body));}
 private async access(user:DemoUser,token:string,command?:z.infer<typeof demoCommandInput>){
  const key=demoWorkspaceKey(user,token);
  return this.db.$transaction(async tx=>{
   // Bound public storage and serialize revision checks across application replicas.
   await tx.$queryRaw`SELECT pg_advisory_xact_lock(hashtext('selfguard-demo-workspaces'))::text`;
   const now=Date.now();await tx.setting.deleteMany({where:{key:{startsWith:prefix},value:{path:['expiresAt'],lte:now}}});
   const row=await tx.setting.findUnique({where:{key}}),stored=row?workspaceInput.parse(row.value):undefined;
   if(!stored&&await tx.setting.count({where:{key:{startsWith:prefix}}})>=500)throw new ConflictException('体验人数较多，请稍后再试');
   const current=stored&&stored.expiresAt>now?stored:newDemoWorkspace(now),next=command?applyDemoCommand(current,command,now):current;
   if(!stored||stored.expiresAt<=now||command)await tx.setting.upsert({where:{key},create:{key,value:next},update:{value:next}});
   return next;
  },{timeout:10000});
 }
}
type DemoRequest={user:DemoUser;headers:{authorization?:string}};
@Controller('demo-workspace') @UseGuards(AuthGuard)
export class DemoWorkspaceController{
 constructor(@Inject(DemoWorkspaceService)private service:DemoWorkspaceService){}
 @Get() @Header('Cache-Control','no-store')read(@Req()r:DemoRequest){return this.service.read(r.user,bearer(r));}
 @Post() @Header('Cache-Control','no-store')command(@Req()r:DemoRequest,@Body()body:unknown){return this.service.command(r.user,bearer(r),body);}
}
