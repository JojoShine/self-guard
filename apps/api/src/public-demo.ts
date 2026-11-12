import {z} from 'zod';
import {basePath} from './platform-path';
export const DEMO_EMAIL='demo@selfguard.local';
export const DEMO_SETTING='public-demo-account';
const demoInput=z.object({enabled:z.literal(true),userId:z.string().uuid(),email:z.literal(DEMO_EMAIL),password:z.string().min(1).max(256),assetIds:z.array(z.string().uuid()).max(1000)}).strict();
const demoUser=z.object({id:z.string(),email:z.literal(DEMO_EMAIL),role:z.literal('VIEWER'),disabled:z.literal(false),dataScope:z.object({restricted:z.literal(true),businesses:z.array(z.string()).length(0),assetIds:z.array(z.string().uuid()),databaseInstanceIds:z.array(z.string()).length(0).optional(),canReadEvidence:z.literal(false),canReadSqlEvidence:z.literal(false),canReadAccessEvidence:z.literal(false),canExportAccessEvidence:z.literal(false)}).strict()});
export function safeDemoAccount(value:unknown,user:unknown){
 const config=demoInput.safeParse(value),account=demoUser.safeParse(user);
 if(!config.success||!account.success)return null;
 const expected=config.data.assetIds,actual=account.data.dataScope.assetIds;
 if(config.data.userId!==account.data.id||new Set(expected).size!==expected.length||new Set(actual).size!==actual.length||expected.length!==actual.length||expected.some(id=>!actual.includes(id)))return null;
 return config.data;
}
export function demoRequestAllowed(method:string,path:string,deploymentPath:string){
 const prefix=basePath(deploymentPath)+'/api';
 if(!path.startsWith(prefix+'/'))return false;
 const route=path.slice(prefix.length);
 if(method==='POST')return route==='/auth/logout';
 if(method!=='GET')return false;
 return ['/auth/me','/overview','/assets','/findings'].includes(route)||/^\/(?:assets|findings)\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(route);
}
