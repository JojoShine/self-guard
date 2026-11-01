import {request} from 'node:https';import {lookup} from 'node:dns';import {createHash} from 'node:crypto';
import {publicAddress} from './advisories';import {sourceProxyAgent} from './intelligence-proxy';import {SourceFetchError,retryAfterSeconds} from './source-fetch-error';
import {onSourceAbort,recordSourceManifest,captureRawChunks} from './intelligence-artifacts';import type {OfficialByteStream} from './intelligence-stream-fetch';
const archiveLimit=1024*1024*1024,chunkBytes=8*1024*1024,parallel=4;

// This profile is restricted to Canonical's Ubuntu archive exported by OSV.
// Pin every byte range to one object generation; CRC is verified by the ZIP reader.
export async function openUbuntuArchive(url:URL,transport:typeof request=request):Promise<OfficialByteStream>{
 if(url.href!=='https://storage.googleapis.com/osv-vulnerabilities/Ubuntu/all.zip')throw Error('Ubuntu归档地址不在官方允许范围');
 let reason:Error|undefined,disposed=false,detach=()=>{};const active=new Set<ReturnType<typeof request>>();
 const abort=(error:Error)=>{if(reason)return;reason=error;for(const req of active)req.destroy(error)};
 const timer=setTimeout(()=>abort(Error('Ubuntu完整归档下载超过30分钟限制')),1800000);timer.unref();
 detach=onSourceAbort(abort);
 function dispose(){if(disposed)return;disposed=true;detach();clearTimeout(timer);abort(Error('Ubuntu归档读取已结束'))}
 async function range(start:number,end:number,generation?:string):Promise<{body:Buffer;generation:string;total:number;crc32c?:string}>{
  if(reason)throw reason;
  return new Promise((resolve,reject)=>{
   let req:ReturnType<typeof request>|undefined,agent:ReturnType<typeof sourceProxyAgent>=false,settled=false;const parts:Buffer[]=[];let length=0;
   const finish=(error?:Error,value?:{body:Buffer;generation:string;total:number;crc32c?:string})=>{if(settled)return;settled=true;clearTimeout(timeout);if(req)active.delete(req);if(agent)agent.destroy();if(error){req?.destroy(error);reject(reason||error)}else resolve(value!)};
   const timeout=setTimeout(()=>finish(Error('Ubuntu归档区间读取超过3分钟限制')),180000);timeout.unref();
   try{agent=sourceProxyAgent(url);req=transport(url,{agent,rejectUnauthorized:true,maxHeaderSize:16384,headers:{Range:`bytes=${start}-${end}`,'accept-encoding':'identity','user-agent':'SelfGuard-Intelligence/1.0',...(generation?{'x-goog-if-generation-match':generation}:{})},lookup:((hostname:any,options:any,callback:any)=>lookup(hostname,{all:true,verbatim:true},(error,addresses)=>{if(error)return callback(error);if(!addresses.length||addresses.some(a=>!publicAddress(a.address)))return callback(Error('来源DNS指向非公开地址'));return options?.all?callback(null,addresses):callback(null,addresses[0].address,addresses[0].family)})) as any},response=>{
    if(response.statusCode!==206){response.resume();return finish(new SourceFetchError('Ubuntu区间响应状态 '+response.statusCode+'，不接受重定向或整包替代',retryAfterSeconds(response.headers['retry-after'])))}
    const encoding=String(response.headers['content-encoding']||'identity'),received=String(response.headers['x-goog-generation']||''),match=/^bytes (\d+)-(\d+)\/(\d+)$/.exec(String(response.headers['content-range']||''));
    if(encoding!=='identity'||!match||Number(match[1])!==start||Number(match[2])!==end||!/^\d{1,30}$/.test(received)||generation&&received!==generation){response.resume();return finish(Error('Ubuntu归档区间、编码或固定版本不一致'))}
    const total=Number(match[3]);if(!Number.isSafeInteger(total)||total<1||total>archiveLimit||end>=total){response.resume();return finish(Error('Ubuntu归档总量超过1GiB预算或区间无效'))}
    const crc32c=String(response.headers['x-goog-hash']||'').match(/(?:^|,)\s*crc32c=([A-Za-z0-9+/]{6}==)/)?.[1];
    if(!generation&&!crc32c){response.resume();return finish(Error('Ubuntu官方归档缺少完整CRC32C依据'))}
    response.on('data',part=>{length+=part.length;if(length>end-start+1){finish(Error('Ubuntu归档区间超过声明长度'));return}parts.push(Buffer.from(part))});
    response.on('aborted',()=>finish(Error('Ubuntu归档区间响应中断')));response.on('error',error=>finish(error));
    response.on('end',()=>{if(length!==end-start+1)return finish(Error('Ubuntu归档区间未完整结束'));finish(undefined,{body:Buffer.concat(parts),generation:received,total,crc32c})});
   });active.add(req);req.on('error',error=>finish(error));req.end();}catch(error){finish(error instanceof Error?error:Error('Ubuntu归档连接失败'))}
  });
 }
 try{
  const probe=await range(0,0),hash=createHash('sha256'),result:OfficialByteStream={chunks:undefined as any,sourceSha256:'',decodedBytes:0,generation:probe.generation,crc32c:probe.crc32c,abort:dispose};
  recordSourceManifest('http',{generation:probe.generation,crc32c:probe.crc32c,contentLength:probe.total,rangeProfile:'selfguard-ubuntu-ranges-v1',chunkBytes,parallel,batchIntervalMs:1000});
  async function* chunks(){let previousBatch=0;try{
   for(let offset=0;offset<probe.total;offset+=chunkBytes*parallel){
    if(reason)throw reason;const wait=1000-(Date.now()-previousBatch);if(wait>0)await new Promise(resolve=>setTimeout(resolve,wait));if(reason)throw reason;previousBatch=Date.now();
    const pending=[];for(let index=0;index<parallel&&offset+index*chunkBytes<probe.total;index++){const start=offset+index*chunkBytes;pending.push(range(start,Math.min(start+chunkBytes,probe.total)-1,probe.generation))}
    const batch=await Promise.all(pending);for(const part of batch){if(reason)throw reason;if(part.total!==probe.total)throw Error('Ubuntu固定版本归档大小改变');hash.update(part.body);result.decodedBytes+=part.body.length;yield part.body}
   }
   if(reason)throw reason;if(result.decodedBytes!==probe.total)throw Error('Ubuntu归档字节总量不一致');result.sourceSha256=hash.digest('hex');
  }finally{dispose()}}
  result.chunks=captureRawChunks(chunks(),'ZIP');return result;
 }catch(error){dispose();throw error}
}
