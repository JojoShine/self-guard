import {z} from 'zod';
import {basePath} from './platform-path';
export const DEMO_EMAIL='demo@selfguard.local';
export const DEMO_SETTING='public-demo-account';
const demoInput=z.object({enabled:z.literal(true),userId:z.string().uuid(),email:z.literal(DEMO_EMAIL),password:z.string().min(1).max(256),assetIds:z.array(z.string().uuid()).max(1000),accessMode:z.literal('FULL_READ_ONLY').optional()}).strict();
const demoUser=z.object({id:z.string(),email:z.literal(DEMO_EMAIL),role:z.literal('VIEWER'),disabled:z.literal(false),dataScope:z.object({restricted:z.boolean(),businesses:z.array(z.string()).length(0),assetIds:z.array(z.string().uuid()),databaseInstanceIds:z.array(z.string()).length(0).optional(),canReadEvidence:z.literal(false),canReadSqlEvidence:z.literal(false),canReadAccessEvidence:z.literal(false),canExportAccessEvidence:z.literal(false)}).strict()});
export function safeDemoAccount(value:unknown,user:unknown){
 const config=demoInput.safeParse(value),account=demoUser.safeParse(user);
 if(!config.success||!account.success)return null;
 const expected=config.data.assetIds,actual=account.data.dataScope.assetIds;
 if(config.data.accessMode==='FULL_READ_ONLY'){
  if(account.data.dataScope.restricted||expected.length||actual.length||!account.data.dataScope.databaseInstanceIds)return null;
 }else if(!account.data.dataScope.restricted)return null;
 if(config.data.userId!==account.data.id||new Set(expected).size!==expected.length||new Set(actual).size!==actual.length||expected.length!==actual.length||expected.some(id=>!actual.includes(id)))return null;
 return config.data;
}
const publicReaders=new WeakSet<object>();
export function markPublicReadOnlyUser<T extends object>(user:T){publicReaders.add(user);return Object.assign(user,{publicReadOnly:true as const});}
export function isPublicReadOnlyUser(user:unknown):boolean{return typeof user==='object'&&user!==null&&publicReaders.has(user);}
const metadataRoutes=new Set([
 '/auth/me','/overview','/discoveries','/waf-access','/waf-nodes','/workload','/workload/details','/asset-changes',
 '/assets','/findings','/tasks','/incidents','/evaluations','/rules','/sites','/users','/audit','/batches','/waf-events',
 '/operations/health','/operations/business-groups','/operations/trends','/operations/notifications','/operations/exports',
 '/governance/approval-policy','/governance/retention','/governance/notification-settings','/governance/notifications','/governance/imports',
 '/maintenance/backup','/maintenance/webhook','/maintenance/deliveries','/storage','/telemetry','/telemetry/policy','/correlation-rules',
 '/database-instances','/database-instances/capabilities','/data-security/policy','/data-security/classifications','/data-security/objects','/data-security/events',
 '/access-observations','/access-sources','/network-sensors','/network-sensors/events','/security-readiness',
 '/asset-candidates','/asset-candidates/policy','/agent-platform','/agent-releases','/agent-installations','/agent-installations/options','/agent-install-batches','/rollouts','/probe-deployments',
 '/probe-rule-library','/probe-templates','/probe-templates/options','/probe-templates/sources','/scan-endpoints','/scan-endpoints/options',
 '/scan-execution-identities','/scan-execution-identities/options','/scan-plans','/scan-plans/options','/active-scan-plans','/active-scan-plans/options',
 '/vulnerability-feeds','/vulnerability-feeds/catalog','/vulnerability-workspace','/vulnerability-workspace/lookup','/advisories/sources',
 '/waf-rule-bundles','/waf-rule-deployments','/waf-rule-deployments/options','/rule-sources/status','/rule-tools/catalog/database','/repair-templates','/certificates','/host-waf/options','/workflows/batches',
]);
const uuid='[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}';
const metadataPatterns=[
 new RegExp('^/(?:assets|findings|tasks|incidents|evaluations|rules|sites|users|waf-events|database-instances|probe-templates|rule-tools|waf-rule-bundles|access-observations)/'+uuid+'$','i'),
 new RegExp('^/assets/'+uuid+'/resource-monitor$','i'),
 new RegExp('^/database-instances/'+uuid+'/(?:collection|runtime-monitor|onboarding)$','i'),
 new RegExp('^/(?:data-security/events|network-sensors/events)/'+uuid+'$','i'),
 new RegExp('^/findings/'+uuid+'/triage$','i'),
 new RegExp('^/(?:scan-plans|active-scan-plans)/'+uuid+'/runs$','i'),
 new RegExp('^/(?:scan-plans|active-scan-plans)/runs/'+uuid+'/targets$','i'),
 new RegExp('^/active-scan-plans/targets/'+uuid+'/checks$','i'),
 new RegExp('^/vulnerability-feeds/'+uuid+'/(?:snapshots|records)$','i'),
 new RegExp('^/host-waf/assets/'+uuid+'/report$','i'),
 new RegExp('^/asset-remote/'+uuid+'/traffic-monitor$','i'),
 new RegExp('^/workflows/(?:assets|findings|incidents|tasks)/'+uuid+'/(?:context|relations)$','i'),
 new RegExp('^/(?:assets|findings|tasks|incidents|evaluations|rules|sites)/'+uuid+'/(?:versions|attachments)$','i'),
 /^\/record-options\/(?:assets|findings|tasks|incidents|rules|sites|users|business-groups|database-instances)$/,
];
export function demoRequestAllowed(method:string,path:string,deploymentPath:string,accessMode?:'FULL_READ_ONLY'){
 const prefix=basePath(deploymentPath)+'/api';
 if(!path.startsWith(prefix+'/'))return false;
 const route=path.slice(prefix.length);
 if(accessMode==='FULL_READ_ONLY')return method==='POST'?route==='/auth/logout':method==='GET'&&(metadataRoutes.has(route)||metadataPatterns.some(pattern=>pattern.test(route)));
 if(route==='/demo-workspace')return method==='GET'||method==='POST';
 if(method==='POST')return route==='/auth/logout';
 if(method!=='GET')return false;
 return ['/auth/me','/overview','/assets','/findings'].includes(route)||/^\/(?:assets|findings)\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(route);
}
