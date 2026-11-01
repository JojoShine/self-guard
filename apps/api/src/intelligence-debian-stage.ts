import {intelligenceRecordFingerprint,intelligenceSnapshotFingerprint} from './intelligence-fingerprint';
import {ConflictException} from '@nestjs/common';import {Db} from './db';import {normalizeDebianPackage,type DebianRelease} from './intelligence-debian';import {isDebianStream} from './intelligence-debian-fetch';
export async function stageDebianSnapshot(db:Db,feed:any,snapshotId:string,leaseId:string,fetched:{document:unknown;sourceSha256:string}){
 const document=fetched.document;if(!isDebianStream(document))throw Error('Debian全量来源必须通过流式读取器接入');
 const hashes:string[]=[],rows:any[]=[];let packages=0,lastRenew=0,batchBytes=0;
 async function renew(tx:any){const held=await tx.vulnerabilityFeed.updateMany({where:{id:feed.id,leaseId,enabled:true,configHash:feed.configHash,leaseUntil:{gt:new Date()}},data:{leaseUntil:new Date(Date.now()+300000)}});if(!held.count)throw new ConflictException('来源已停用、更改或租约过期');lastRenew=Date.now()}
 async function flush(){if(!rows.length)return;const batch=rows.splice(0);batchBytes=0;await db.$transaction(async tx=>{await renew(tx);await tx.vulnerabilityRecord.createMany({data:batch});await tx.vulnerabilitySnapshot.update({where:{id:snapshotId},data:{recordCount:hashes.length,coverage:'已校验 '+hashes.length+' 条所选发行版通告；全文尚未完整结束，仍不可作为扫描依据'}})},{timeout:30000})}
 try{for await(const [name,raw]of document.entries){packages++;if(Date.now()-lastRenew>10000)await renew(db);
   for(const record of normalizeDebianPackage(name,raw,(feed.config as any).release as DebianRelease)){if(hashes.length>=250000)throw Error('所选发行版超过25万条情报限制');const normalizedSha256=intelligenceRecordFingerprint(record),size=Buffer.byteLength(JSON.stringify(record));if(batchBytes+size>4*1024*1024)await flush();hashes.push(normalizedSha256);rows.push({...record,normalizedSha256,snapshotId,scores:record.scores as any,affected:record.affected as any,references:record.references as any,metadata:record.metadata as any});batchBytes+=size;if(rows.length>=500)await flush()}
  }await flush();if(!packages||!hashes.length)throw Error('Debian来源范围为空，未替换有效快照');if(!/^[a-f0-9]{64}$/.test(fetched.sourceSha256))throw Error('来源未完整读取，缺少最终摘要');
  return {version:'Debian/'+(feed.config as any).release+'@'+fetched.sourceSha256.slice(0,16),coverage:'Debian官方安全跟踪器全量软件包中所选发行版；按实际源包和源版本、厂商修复/未修复/不受影响状态核对，待确认状态不产生确认风险',recordCount:hashes.length,contentSha256:intelligenceSnapshotFingerprint(hashes)};
 }finally{document.abort()}
}
