import {SourceFetchError,retryAfterSeconds} from './source-fetch-error';
import {request} from 'node:https';import {lookup} from 'node:dns';import {createGunzip} from 'node:zlib';import {createHash} from 'node:crypto';import {publicAddress} from './advisories';import {sourceProxyAgent} from './intelligence-proxy';
import {Transform} from 'node:stream';
import {captureRawChunks,recordSourceManifest,onSourceAbort,currentRawArchive} from './intelligence-artifacts';
export type OfficialByteStream={chunks:AsyncIterable<Uint8Array>;sourceSha256:string;decodedBytes:number;abort:()=>void;generation?:string;crc32c?:string;storedBytes?:number};
export async function openOfficialStream(url:URL,mode:'HTTP_JSON'|'GZIP_FILE'|'ZIP_FILE'|'TEXT'|'OSV_INDEX'|'OSV_RECORD',transport:typeof request=request):Promise<OfficialByteStream>{
 const indexSource=url.hostname==='storage.googleapis.com'&&/^\/osv-vulnerabilities\/(?:Go|Maven|PyPI|npm|Rocky%20Linux|Ubuntu)\/modified_id\.csv$/.test(url.pathname);
 const recordSource=url.hostname==='storage.googleapis.com'&&/^\/osv-vulnerabilities\/(?:Go|Maven|PyPI|npm|Rocky%20Linux|Ubuntu)\/(?:[A-Za-z0-9._+-]|%3A|%2B){1,600}\.json$/.test(url.pathname);
 const allowed=indexSource||recordSource||url.hostname==='security-tracker.debian.org'&&url.pathname==='/tracker/data/json'||url.hostname==='nvd.nist.gov'&&/^\/feeds\/json\/cve\/2\.0\/nvdcve-2\.0-(?:\d{4}|modified)\.(?:meta|json\.gz)$/.test(url.pathname)||url.hostname==='storage.googleapis.com'&&/^\/osv-vulnerabilities\/(?:Go|Maven|PyPI|npm|Rocky%20Linux)\/all\.zip$/.test(url.pathname);
 if(!allowed||((mode==='OSV_INDEX')!==indexSource)||((mode==='OSV_RECORD')!==recordSource)||url.protocol!=='https:'||url.port||url.username||url.password||url.search||url.hash)throw Error('完整来源地址不在官方允许范围');
 const metadata=mode==='TEXT'||mode==='OSV_INDEX',smallObject=mode==='OSV_RECORD',transferLimit=smallObject?4*1024*1024:mode==='OSV_INDEX'?64*1024*1024:mode==='TEXT'?32768:mode==='ZIP_FILE'?256*1024*1024:128*1024*1024,decodedLimit=smallObject?4*1024*1024:mode==='OSV_INDEX'?64*1024*1024:mode==='TEXT'?32768:1024*1024*1024;
 return new Promise((resolve,reject)=>{
  let req:ReturnType<typeof request>|undefined,body:any,agent:ReturnType<typeof sourceProxyAgent>=false,headersReceived=false,detach=()=>{};
  const close=()=>{detach();clearTimeout(timer);req?.destroy();body?.destroy();if(agent)agent.destroy()};
  const fail=(error:Error)=>{detach();body?.destroy(error);req?.destroy(error);if(agent)agent.destroy();clearTimeout(timer);if(!headersReceived)reject(error)};
  const timer=setTimeout(()=>fail(Error(metadata?'来源元数据请求超过30秒':'完整来源下载超过30分钟限制')),metadata||smallObject?30000:1800000);timer.unref();
  detach=onSourceAbort(fail);if(currentRawArchive()?.cancelled)return;
  try{agent=sourceProxyAgent(url);req=transport(url,{agent,rejectUnauthorized:true,maxHeaderSize:16384,headers:{accept:metadata?'text/plain, text/csv':mode==='GZIP_FILE'?'application/gzip, application/octet-stream, */*':'application/json','accept-encoding':mode==='HTTP_JSON'?'gzip':'identity','user-agent':'SelfGuard-Intelligence/1.0'},lookup:((hostname:any,options:any,callback:any)=>lookup(hostname,{all:true,verbatim:true},(error,addresses)=>{if(error)return callback(error);if(!addresses.length||addresses.some(a=>!publicAddress(a.address)))return callback(Error('来源DNS指向非公开地址'));return options?.all?callback(null,addresses):callback(null,addresses[0].address,addresses[0].family)})) as any},response=>{
   if(response.statusCode!==200){response.resume();return fail(new SourceFetchError('完整来源HTTP状态 '+response.statusCode+'，不跟随重定向',retryAfterSeconds(response.headers['retry-after'])))}
   const encoding=String(response.headers['content-encoding']||'identity').toLowerCase();if(!['identity','gzip'].includes(encoding)){response.resume();return fail(Error('完整来源内容编码未支持'))}
   // A standalone data listener would drain a small identity response before
   // the awaiting caller attaches its iterator. Count through a buffering,
   // backpressured transform instead, so every byte reaches the decoder.
   let transferred=0;const counted=new Transform({transform(chunk,_encoding,callback){transferred+=chunk.length;callback(transferred>transferLimit?Error('完整来源传输超过预算'):null,chunk)}});counted.on('error',fail);response.on('error',fail);response.on('aborted',()=>fail(Error('完整来源响应中断')));response.pipe(counted);
   let decoded:any=encoding==='gzip'?counted.pipe(createGunzip()):counted;decoded.on('error',()=>{});if(mode==='GZIP_FILE'){const outer=decoded;decoded=outer.pipe(createGunzip());outer.on('error',(error:Error)=>decoded.destroy(error))}body=decoded;body.on('error',()=>{});
   const hash=createHash('sha256'),result:OfficialByteStream={chunks:undefined as any,sourceSha256:'',decodedBytes:0,abort:close};const generation=String(response.headers['x-goog-generation']||''),googleHash=String(response.headers['x-goog-hash']||'');if(/^\d{1,30}$/.test(generation))result.generation=generation;result.crc32c=googleHash.match(/(?:^|,)\s*crc32c=([A-Za-z0-9+/]{6}==)/)?.[1];
   if(mode==='OSV_INDEX'||smallObject){const stored=String(response.headers['x-goog-stored-content-length']||'');if(!result.generation||!result.crc32c||!/^\d+$/.test(stored)||Number(stored)<1||Number(stored)>decodedLimit)return fail(Error('OSV更新索引缺少有效对象版本、大小或CRC32C'));result.storedBytes=Number(stored)}
   async function* chunks(){try{for await(const part of body){const bytes=Buffer.from(part);result.decodedBytes+=bytes.length;if(result.decodedBytes>decodedLimit)throw Error('完整来源解压超过预算');hash.update(bytes);yield bytes}result.sourceSha256=hash.digest('hex')}finally{close()}}
   if(mode!=='TEXT'&&!smallObject)recordSourceManifest(mode==='OSV_INDEX'?'osvIndexHttp':'http',{etag:response.headers.etag||null,lastModified:response.headers['last-modified']||null,contentLength:response.headers['content-length']||null,generation:result.generation||null,googleHash:googleHash||null});
   result.chunks=metadata||smallObject?chunks():captureRawChunks(chunks(),mode==='ZIP_FILE'?'ZIP':'GZIP_JSON');headersReceived=true;resolve(result);
  });req.on('error',fail);req.setTimeout(30000,()=>fail(Error('完整来源连接连续30秒没有数据')));req.end()}catch(error){fail(error as Error)}
 });
}
