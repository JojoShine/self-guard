import {z} from 'zod';
import {BadRequestException} from '@nestjs/common';
import {hostWafBindingInput} from './host-waf';
const file=z.string().regex(/^\/[A-Za-z0-9_./-]+$/).max(1000).refine(value=>!value.includes('//')&&!value.split('/').some(part=>part==='.'||part==='..'));
export const nginxRemoteInput=hostWafBindingInput.omit({assetId:true}).extend({siteId:z.string().uuid(),businessMode:z.enum(['EXISTING','NEW']).default('EXISTING'),listenPort:z.number().int().min(1).max(65535).optional(),certificateFile:file.optional(),certificateKeyFile:file.optional()}).strict().superRefine((value,ctx)=>{const fail=(message:string)=>ctx.addIssue({code:'custom',message});if(value.businessMode==='EXISTING'){if(value.listenPort!==undefined||value.certificateFile||value.certificateKeyFile)fail('现有业务保留原端口和证书，不填写新业务字段');return}const entry=new URL(value.entryUrl),port=Number(entry.port||(entry.protocol==='https:'?443:80));if(value.listenPort!==port)fail('新站点监听端口必须与本机入口一致');if(entry.protocol==='https:'?!(value.certificateFile&&value.certificateKeyFile):!!(value.certificateFile||value.certificateKeyFile))fail('HTTPS需填写目标主机上的证书和私钥文件；HTTP不填写证书');if(value.listenPort===value.wafPort)fail('Nginx入口与WAF端口不能相同');});
const digest=z.string().regex(/^[a-f0-9]{64}$/);
export const nginxPreflightResult=z.object({schema:z.literal('selfguard-nginx-preflight-v1'),assetId:z.string().uuid(),siteId:z.string().uuid(),businessMode:z.enum(['EXISTING','NEW']),hostname:z.string().min(1).max(253),nginxConfig:file,configSha256:z.union([z.literal('ABSENT'),digest]),nginxSha256:digest,plannedConfigSha256:digest,cpuQuota:z.number().positive().max(4).optional(),memoryLimitBytes:z.number().int().positive().max(1073741824).optional(),changes:z.array(z.string().max(500)).min(1).max(20),preserved:z.array(z.string().max(500)).max(20)}).strict().refine(value=>(value.businessMode==='NEW')===(value.configSha256==='ABSENT'),'预检配置指纹与新旧业务类型不符');
export type NginxAction='PREFLIGHT'|'APPLY'|'ROLLBACK';
export function remoteNginxCommand(id:string,action:NginxAction){if(!/^[a-f0-9-]{36}$/.test(id)||!['PREFLIGHT','APPLY','ROLLBACK'].includes(action))throw new BadRequestException('Nginx任务标识或操作无效');const flag={PREFLIGHT:'--preflight-nginx',APPLY:'--onboard-nginx',ROLLBACK:'--rollback-nginx-plan'}[action];return `bash -c 'set -euo pipefail
umask 077
[ "$(id -u)" = 0 ]
[ -x /opt/selfguard-agent/current ]
base=/var/lib/selfguard-host-waf
[ ! -L "$base" ]
mkdir -p "$base"
[ "$(stat -c %u "$base")" = 0 ]
chmod 700 "$base"
work=$(mktemp -d "$base/remote-${id}.XXXXXX")
cat > "$work/plan.json"
exec /opt/selfguard-agent/current ${flag} "$work/plan.json"
'`;}
export const nginxPlanInput=nginxRemoteInput.safeExtend({schema:z.literal('selfguard-nginx-v1'),assetId:z.string().uuid(),hostname:z.string().min(1).max(253),upstream:z.string().url().max(2048),image:z.string().regex(/^(?:sha256:[a-f0-9]{64}|[A-Za-z0-9./_:-]+@sha256:[a-f0-9]{64})$/),mode:z.enum(['OBSERVE','BLOCK']),wafCPUQuota:z.literal(4).optional(),wafMemoryBytes:z.literal(1073741824).optional(),imageArchiveSha256:digest.optional(),imageArchiveBytes:z.number().int().positive().max(64*1024*1024).optional(),expectedConfigSha256:z.union([z.literal('ABSENT'),digest]).optional(),expectedNginxSha256:digest.optional(),expectedPlannedConfigSha256:digest.optional()});
export const nginxJobConfig=z.object({schema:z.literal('selfguard-nginx-job-v1'),action:z.enum(['PREFLIGHT','APPLY','ROLLBACK']),plan:nginxPlanInput,siteVersion:z.number().int().positive(),previewJobId:z.string().uuid().optional(),reason:z.string().min(5).max(1000).optional()}).strict();
export const nginxOperationResult=z.object({schema:z.literal('selfguard-nginx-v1'),siteId:z.string().uuid(),mode:z.enum(['OBSERVE','BLOCK']),status:z.enum(['VERIFIED','FAILED','ROLLED_BACK']),updatedAt:z.iso.datetime({offset:true}),transactionDir:z.string().max(1000),message:z.string().max(1000)}).strict();
export {supportsHostWafAutomation as supportsNginxAutomation} from './host-waf';
