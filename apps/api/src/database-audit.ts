import {sealDatabaseSql,sqlExpiresAt} from './database-sql';
import {ruleAppliesToAsset} from './rule-tools';
import {createHash} from 'node:crypto';import {BlockList,isIP} from 'node:net';import {BadRequestException,ConflictException,ForbiddenException,HttpException} from '@nestjs/common';import {Prisma} from '@prisma/client';import {z} from 'zod';import {DatabaseEvent,databaseEventInput} from './database-contract';import {classificationBasis,classificationPolicy} from './data-governance';import type {Platform} from './platform';
const configInput=z.object({type:z.enum(['DATABASE_AUTH','DATABASE_CLEARTEXT','DATABASE_ACTIVITY','DATABASE_ACCESS']),instanceId:z.string().uuid().optional(),engines:z.array(z.string()).optional(),operations:z.array(z.string()).optional(),minimumRows:z.number().optional(),requireSuccess:z.boolean().optional(),detectPermissionDenied:z.boolean().optional(),allowUsers:z.array(z.string()).optional(),allowSources:z.array(z.string()).optional(),allowedHours:z.array(z.number()).optional(),timeZone:z.string().optional(),threshold:z.number().optional(),windowSeconds:z.number().optional(),path:z.string().optional(),service:z.string().optional()});
export function databaseEventMatches(raw:unknown,event:DatabaseEvent){const p=configInput.safeParse(raw);if(!p.success)return false;const c=p.data;if(c.engines?.length&&!c.engines.includes(event.service))return false;if(c.instanceId&&c.instanceId!==event.instanceId)return false;
 if(c.type==='DATABASE_AUTH')return event.operation==='LOGIN'&&event.succeeded===false&&!!event.sourceIp;
 if(c.type==='DATABASE_CLEARTEXT')return event.operation==='LOGIN'&&event.succeeded===true&&event.tls===false;
 if(c.type==='DATABASE_ACTIVITY')return !!c.operations?.includes(event.operation)&&(c.minimumRows===undefined||(event.rows!==undefined&&event.rows>=c.minimumRows))&&(!c.requireSuccess||event.succeeded===true);
 if(c.detectPermissionDenied&&event.permissionGranted===false)return true;
 if(event.operation!=='LOGIN'||event.succeeded!==true)return false;
 if(c.allowUsers?.length&&!c.allowUsers.includes(event.user))return true;
 if(c.allowSources?.length&&event.sourceIp){const list=new BlockList();for(const source of c.allowSources){const[address,prefix]=source.split('/');const family=isIP(address)===6?'ipv6':'ipv4';if(prefix===undefined)list.addAddress(address,family);else list.addSubnet(address,Number(prefix),family);}if(!list.check(event.sourceIp,isIP(event.sourceIp)===6?'ipv6':'ipv4'))return true;}
 if(c.allowedHours?.length){const hour=Number(new Intl.DateTimeFormat('en-GB',{timeZone:c.timeZone||'UTC',hour:'2-digit',hourCycle:'h23'}).format(new Date(event.timestamp)));if(!c.allowedHours.includes(hour))return true;}
 return false;
}
export async function ingestDatabaseEvents(tx:Prisma.TransactionClient,p:Pick<Platform,'ingest'>,events:DatabaseEvent[],collectorAssetId?:string){
 await tx.$queryRaw`SELECT pg_advisory_xact_lock(hashtext(current_schema()),hashtext('database-audit-storage'))::text`;
 let retained=await tx.databaseAudit.count();let sqlBytes:number|undefined;
 const result={accepted:0,duplicates:0,alerts:0};const policy=await classificationPolicy(tx);const rules=await tx.rule.findMany({where:{enabled:true,kind:'LOG'}});const collector=collectorAssetId?await tx.asset.findUnique({where:{id:collectorAssetId}}):null;
 for(const raw of events){const input=databaseEventInput.parse(raw);const sql=input.execution?.sql;const event={...input,...(input.execution?{execution:(({sql:ignored,...metadata})=>metadata)(input.execution)}:{})};if(Date.parse(event.timestamp)>Date.now()+300000)throw new BadRequestException('审计时间超前超过5分钟');
 const instance=await tx.databaseInstance.findUnique({where:{id:event.instanceId}});if(!instance||instance.archivedAt)throw new ConflictException('数据库实例不存在或已归档');if(instance.engine!==event.service)throw new BadRequestException('审计数据库类型与实例不符');if(collectorAssetId&&!instance.hostIds.includes(collectorAssetId))throw new ForbiddenException('此Agent没有绑定该实例的采集授权');
 const dedupKey=createHash('sha256').update(JSON.stringify([event.instanceId,event.eventId])).digest('hex');await tx.$queryRaw`SELECT pg_advisory_xact_lock(hashtext(current_schema()),hashtext(${dedupKey}))::text`;
 if(await tx.databaseAudit.findUnique({where:{dedupKey}})){result.duplicates++;continue;}
 if(retained>=100000)throw new HttpException('数据库审计已达100000条上限，请清理到期记录；未确认的Agent队列将保留',507);retained++;
 const objectDatabases=[...new Set([...(event.database?[event.database]:[]),...event.objects.map(o=>o.database)])];const definitions=objectDatabases.length?await tx.dataClassification.findMany({where:{instanceId:instance.id,database:{in:objectDatabases},status:'ACTIVE'}}):[];const {severity:riskFloor,...snapshot}=classificationBasis(event,definitions,'INFO',policy);const classification={...snapshot,riskFloor,riskEvaluation:'AUDIT_ONLY_UNTIL_RULE_MATCH'};
 const audit=await tx.databaseAudit.create({data:{dedupKey,eventId:event.eventId,instanceId:instance.id,collectorAssetId,engine:event.service,database:event.database,schema:event.schema,table:event.table,user:event.user,sourceIp:event.sourceIp,operation:event.operation,timestamp:new Date(event.timestamp),level:classification.level,classification,details:event}});result.accepted++;
 if(sql&&sqlExpiresAt(new Date(event.timestamp))>new Date()){if(sqlBytes===undefined)sqlBytes=(await tx.databaseSqlEvidence.aggregate({_sum:{bytes:true}}))._sum.bytes||0;const ciphertext=sealDatabaseSql(audit.id,sql),bytes=Buffer.byteLength(ciphertext);if(sqlBytes+bytes>256*1024*1024)throw new HttpException('SQL原文密文已达256MiB上限，请等待到期清理；未确认队列仍保留',507);await tx.databaseSqlEvidence.create({data:{auditId:audit.id,ciphertext,bytes,expiresAt:sqlExpiresAt(new Date(event.timestamp))}});sqlBytes+=bytes;}
 const objectRecords=[...(event.database?[{database:event.database,schema:event.schema,table:event.table,columns:event.columns}]:[]),...event.objects];for(const o of objectRecords){const objects=[{database:o.database,schema:'',table:'',column:''},...(o.table?[{database:o.database,schema:o.schema||'',table:o.table,column:''},...o.columns.map(column=>({database:o.database,schema:o.schema||'',table:o.table!,column}))]:[])];for(const object of objects){const key={instanceId:instance.id,...object};await tx.dataObject.upsert({where:{instanceId_database_schema_table_column:key},create:{...key,source:'AUDIT_OBSERVED'},update:{lastSeen:new Date()}});}}

 for(const rule of rules){const parsed=configInput.safeParse(rule.config);if(!parsed.success||parsed.data.instanceId!==instance.id||!databaseEventMatches(rule.config,event))continue;const c=parsed.data;if(c.path&&event.sourcePath!==c.path)continue;if(collector&&!ruleAppliesToAsset(rule.config,collector))continue;if(!collector&&(rule.config as {applicability?:unknown}).applicability)continue;const seconds=c.windowSeconds||60;const threshold=c.type==='DATABASE_CLEARTEXT'?1:c.threshold||1;
 if(Date.parse(event.timestamp)<Date.now()-seconds*1000)continue;
 const objectGroup=c.type==='DATABASE_ACTIVITY'?{user:event.user,operation:event.operation,database:event.database||null,schema:event.schema||null,table:event.table||null}:{};
 const where:Prisma.DatabaseAuditWhereInput={instanceId:instance.id,...objectGroup,sourceIp:event.sourceIp||null,collectorAssetId:collectorAssetId||null,...(event.objects.length?{details:{path:['objects'],equals:event.objects}}:{}),timestamp:{gte:new Date(Date.parse(event.timestamp)-seconds*1000),lte:new Date(event.timestamp)},AND:[...(c.path?[{details:{path:['sourcePath'],equals:c.path}}]:[]),...(event.sourceHost?[{details:{path:['sourceHost'],equals:event.sourceHost}}]:[])]};
 let count=0;
 if((c.type==='DATABASE_ACTIVITY'||c.type==='DATABASE_AUTH'||c.type==='DATABASE_CLEARTEXT')&&(event.sourceIp||event.sourceHost)){
  const filters:Prisma.DatabaseAuditWhereInput[]=[];
  if(c.type==='DATABASE_AUTH'||c.type==='DATABASE_CLEARTEXT'){where.operation='LOGIN';filters.push({details:{path:['succeeded'],equals:c.type==='DATABASE_CLEARTEXT'}})}
  if(c.type==='DATABASE_CLEARTEXT')filters.push({details:{path:['tls'],equals:false}});
  if(c.requireSuccess)filters.push({details:{path:['succeeded'],equals:true}});
  if(c.minimumRows!==undefined)filters.push({details:{path:['rows'],gte:c.minimumRows}});
  where.AND=[...(Array.isArray(where.AND)?where.AND:[]),...filters];count=await tx.databaseAudit.count({where});
 }else{
  let cursor:string|undefined;while(count<threshold){const rows=await tx.databaseAudit.findMany({where,orderBy:{id:'asc'},take:500,...(cursor?{cursor:{id:cursor},skip:1}:{}),select:{id:true,details:true}});for(const row of rows){const e=databaseEventInput.safeParse(row.details);if(e.success&&e.data.sourceHost===event.sourceHost&&databaseEventMatches(rule.config,e.data))count++;}if(rows.length<500)break;cursor=rows[rows.length-1].id;}
 }
 if(count<threshold)continue;

 const basis=classificationBasis(event,definitions,rule.severity,policy);const finding=await p.ingest(tx,{externalId:rule.id+':v'+rule.version+':'+Math.floor(Date.parse(event.timestamp)/(seconds*1000))+':'+createHash('sha256').update(JSON.stringify([collectorAssetId||null,event.sourceIp||null,event.sourceHost||null,objectGroup,event.objects])).digest('hex'),title:rule.name,kind:'ALERT',severity:basis.severity,source:'database-security',instanceId:instance.id,evidence:JSON.stringify({type:'DATABASE_AUDIT',auditId:audit.id,ruleId:rule.id,ruleVersion:rule.version,object:event,classification:basis,action:'DETECT_ONLY',outcome:'NOT_BLOCKED'})});await tx.databaseAudit.update({where:{id:audit.id},data:{findingId:finding.id}});result.alerts++;}
 }
 return result;
}
