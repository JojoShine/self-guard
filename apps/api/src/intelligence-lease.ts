import {cancelRawSource} from './intelligence-artifacts';
// Downloading an archive can take longer than a staging batch. Retain ownership
// during network reads too, without reviving a lease that has already expired.
export async function withIntelligenceLease<T>(db:any,feed:any,leaseId:string,work:()=>Promise<T>,intervalMs=30000):Promise<T>{
 let stopped=false,pending:Promise<void>|undefined;
 const timer=setInterval(()=>{if(stopped||pending)return;pending=(async()=>{try{const held=await db.vulnerabilityFeed.updateMany({where:{id:feed.id,leaseId,enabled:true,configHash:feed.configHash,leaseUntil:{gt:new Date()}},data:{leaseUntil:new Date(Date.now()+300000)}});if(!held.count&&!stopped)cancelRawSource(Error('来源已停用、更改或发布资格已过期'))}catch{if(!stopped)cancelRawSource(Error('来源租约无法续期，已停止继续下载'))}finally{pending=undefined}})()},intervalMs);timer.unref();
 try{return await work()}finally{stopped=true;clearInterval(timer);await pending}
}
