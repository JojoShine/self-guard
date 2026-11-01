import {Body,Controller,Get,Patch,Param,Req,Inject,UseGuards,NotFoundException,ConflictException,BadRequestException} from '@nestjs/common';
import {Prisma} from '@prisma/client';
import {z} from 'zod';
import {Db} from './db';
import {AuthGuard,allow} from './auth';
import {parse} from './validation';

export const repairTemplateCatalog=[
 {id:'FILE_PERMISSION',version:'1',name:'文件权限修复',impact:'仅调整一个允许范围内的普通文件权限。',parameters:[{name:'path',required:true,description:'Agent 本地允许根目录内的绝对路径。'},{name:'mode',required:true,description:'0600、0640 或 0644。'},{name:'healthService',required:false,description:'可选的本地允许列表 .service；独立验证时必须 active。'}],preconditions:['任务已批准，尚未过期且在执行窗口内。','路径位于本地 AllowedRoot，拒绝符号链接、多硬链接及非普通文件。','可选 healthService 必须在本地 AllowedServices 中，未授权时不修改文件。'],steps:['记录原始权限和私有修复计划。','通过安全打开的文件描述符设置批准权限。','立即读取文件权限并持久化执行结果。'],verification:['独立 VERIFY_READ 重新打开目标读取权限。','配置 healthService 时额外执行只读 is-active 检查。','需要执行器验签的资产，仅接受匹配任务和资产的根执行器结果。'],restore:['单独创建并批准 ROLLBACK，引用原始任务。','确认目标仍符合原修复的应用状态，恢复本地记录的原权限。','对回滚任务再次执行独立读回；失败或未知结果保留人工核对。']},
 {id:'CONFIG_VALUE',version:'1',name:'配置值修复',impact:'在单个受控配置文件中替换一个字面键值。',parameters:[{name:'path',required:true,description:'允许范围内的普通配置文件，最多 64 KiB。'},{name:'key',required:true,description:'符合约束且恰好出现一次的字面配置键。'},{name:'expectedValue',required:true,description:'变更前必须匹配的原值。'},{name:'value',required:true,description:'批准的新值，不允许控制字符。'},{name:'healthService',required:false,description:'可选的本地允许列表 .service；不会自动重启。'}],preconditions:['任务已批准，尚未过期且在执行窗口内。','路径和文件类型通过本地安全检查。','配置键恰好出现一次，当前值必须等于 expectedValue。','不存在待处理的配置恢复标记；相关服务已在本地明确允许。'],steps:['保存私有原始备份、修复计划与恢复标记。','仅替换批准的键值并同步文件。','重新读取内容核对；写入失败时尝试恢复原内容。'],verification:['独立 VERIFY_READ 重新读取配置键值。','可选 healthService 必须通过只读 active 检查。','未知/超时结果不能作为风险已消除的依据。'],restore:['批准引用原始任务的 ROLLBACK。','当前目标值必须仍等于原任务的新值，再恢复已记录的原值。','保留无关键，独立验证恢复结果；中断恢复必须核对私有备份和标记。']},
 {id:'SERVICE_STATE',version:'1',name:'服务状态修复',impact:'仅启动或停止明确允许的 systemd 服务，可能影响业务流量。',parameters:[{name:'service',required:true,description:'本地 AllowedServices 中的完整 .service 单元名称。'},{name:'expectedState',required:true,description:'当前必须匹配 active 或 inactive。'},{name:'state',required:true,description:'批准的目标 active 或 inactive。'}],preconditions:['Linux 上存在固定 /usr/bin/systemctl，任务已批准且在有效窗口内。','单元名称通过格式检查并在本地 AllowedServices 中。','实际状态为可恢复的 active/inactive，且等于 expectedState。','不存在未核对的服务恢复标记。'],steps:['记录原始状态、私有计划和服务恢复标记。','仅执行固定 start/stop -- UNIT 操作，不接受命令文本。','读取实际状态；失败时尝试恢复并核对原状态。'],verification:['独立 VERIFY_READ 使用固定只读 is-active 查询。','实际状态必须等于批准目标；超时为未知。','active 状态不能替代业务功能检查，应用健康按运营要求另行核对。'],restore:['批准引用原始任务的 ROLLBACK。','目标仍符合原修复状态时恢复记录的原状态。','命令超时或恢复失败保留标记；核对 systemd 作业和应用状态后再恢复处理。']},
] as const;
function descriptor(id:string){const item=repairTemplateCatalog.find(item=>item.id===id);if(!item)throw new NotFoundException('修复模板不存在');return item;}
function enabled(row:{value:Prisma.JsonValue}|null){if(!row)return true;const value=row.value as any;return value?.version==='1'&&value?.enabled===true;}
async function lock(tx:Prisma.TransactionClient,id:string){await tx.$queryRaw`SELECT pg_advisory_xact_lock(hashtext(${'selfguard-repair-template:'+id}))::text`;}
export async function assertTemplateEnabled(tx:Prisma.TransactionClient,id:string){
 if(id==='ROLLBACK'||id==='VERIFY_READ')return null;
 const template=repairTemplateCatalog.find(item=>item.id===id);if(!template)throw new BadRequestException('不支持的修复模板');
 await lock(tx,id);const setting=await tx.setting.findUnique({where:{key:'repair-template:'+id}});if(!enabled(setting))throw new ConflictException('修复模板已停用，不能创建或领取新的执行任务');return template;
}
@Controller('repair-templates')
@UseGuards(AuthGuard)
export class RepairTemplatesController {
 constructor(@Inject(Db) private db:Db){}
 @Get() async list(){const rows=await this.db.setting.findMany({where:{key:{in:repairTemplateCatalog.map(t=>'repair-template:'+t.id)}}});return {items:repairTemplateCatalog.map(template=>({...template,enabled:enabled(rows.find(row=>row.key==='repair-template:'+template.id)||null)}))};}
 @Patch(':id') async update(@Req() req:any,@Param('id') id:string,@Body() body:unknown){allow(req,['ADMIN']);const template=descriptor(id);const value=parse(z.object({enabled:z.boolean()}).strict(),body);return this.db.$transaction(async tx=>{await lock(tx,id);const state={enabled:value.enabled,version:template.version};await tx.setting.upsert({where:{key:'repair-template:'+id},create:{key:'repair-template:'+id,value:state},update:{value:state}});await tx.audit.create({data:{actor:req.user.email,action:'CONFIGURE',resource:'repair-templates',resourceId:id,detail:state}});return {...template,...state};});}
}
