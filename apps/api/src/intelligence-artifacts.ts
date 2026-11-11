import {AsyncLocalStorage,AsyncResource} from 'node:async_hooks';import {createHash,randomUUID} from 'node:crypto';import {createReadStream,createWriteStream} from 'node:fs';import {mkdir,readdir,lstat,open,link,unlink} from 'node:fs/promises';import {join,resolve} from 'node:path';import {PassThrough,Transform} from 'node:stream';import {pipeline} from 'node:stream/promises';import {once} from 'node:events';import {createGzip} from 'node:zlib';import {HttpException} from '@nestjs/common';
export const intelligenceNormalizerVersion='selfguard-intelligence-v7';
export type RawArtifact={sha256:string;size:number;encoding:'GZIP_JSON'|'GZIP_XML'|'ZIP';payloadSha256:string};
type RawWriter={write:(part:Uint8Array)=>Promise<void>;finish:()=>Promise<RawArtifact>;abort:()=>Promise<void>};
type RawContext={root:string;reservedBytes:number;artifact?:RawArtifact;manifest:Record<string,unknown>;writer?:RawWriter;aborts:Set<(error:Error)=>void>;cancelled?:Error};
const context=new AsyncLocalStorage<RawContext>();
export function intelligenceArtifactRoot(){return resolve(process.env.INTELLIGENCE_ARTIFACT_DIR||join(process.cwd(),'.data','intelligence'))}
export function artifactPath(root:string,sha256:string){if(!/^[a-f0-9]{64}$/.test(sha256))throw Error('原始制品摘要无效');return join(root,'objects',sha256+'.blob')}
async function ensure(root:string){await mkdir(join(root,'objects'),{recursive:true,mode:0o700});await mkdir(join(root,'tmp'),{recursive:true,mode:0o700})}
async function fileHash(path:string){const hash=createHash('sha256');for await(const part of createReadStream(path))hash.update(part);return hash.digest('hex')}
async function missingOkay(path:string){try{await unlink(path)}catch(error){if((error as NodeJS.ErrnoException).code!=='ENOENT')throw error}}
async function rawWriter(scope:RawContext,encoding:RawArtifact['encoding']):Promise<RawWriter>{
 await ensure(scope.root);const partial=join(scope.root,'tmp',randomUUID()+'.partial'),input=new PassThrough({highWaterMark:65536}),compress=encoding!=='ZIP'?createGzip():new PassThrough(),hash=createHash('sha256'),payloadHash=createHash('sha256');let size=0,error:Error|undefined,finished=false;
 const counted=new Transform({transform(part,_encoding,callback){size+=part.length;if(size>scope.reservedBytes)return callback(Error('原始数据超过预留空间上限'));hash.update(part);callback(null,part)}}),output=createWriteStream(partial,{flags:'wx',mode:0o600}),completion=pipeline(input,compress,counted,output);completion.catch(reason=>{error=reason});
 return {
  async write(part){if(error)throw error;payloadHash.update(part);if(!input.write(part))await once(input,'drain');if(error)throw error},
  async finish(){input.end();await completion;const sha256=hash.digest('hex'),payloadSha256=payloadHash.digest('hex'),path=artifactPath(scope.root,sha256),handle=await open(partial,'r');try{await handle.sync()}finally{await handle.close()}
   try{await link(partial,path)}catch(reason){if((reason as NodeJS.ErrnoException).code!=='EEXIST')throw reason;const existing=await lstat(path);if(!existing.isFile()||existing.size!==size||await fileHash(path)!==sha256)throw Error('已有原始制品校验失败，未覆盖')}
   await missingOkay(partial);const directory=await open(join(scope.root,'objects'),'r');try{await directory.sync()}finally{await directory.close()}finished=true;return {sha256,size,encoding,payloadSha256};
  },
  async abort(){if(!finished){input.destroy();await completion.catch(()=>{});await missingOkay(partial)}}
 };
}
export function currentRawArchive(){return context.getStore()}
export function onSourceAbort(handler:(error:Error)=>void){const scope=context.getStore();if(!scope)return()=>{};if(scope.cancelled)handler(scope.cancelled);else scope.aborts.add(handler);return()=>{scope.aborts.delete(handler)}}
export function cancelRawSource(error:Error){const scope=context.getStore();if(!scope||scope.cancelled)return;scope.cancelled=error;for(const handler of scope.aborts){try{handler(error)}catch{}}}
export function recordSourceManifest(key:string,value:unknown){const scope=context.getStore();if(!scope)return;if(!/^[A-Za-z][A-Za-z0-9]{0,50}$/.test(key)||Buffer.byteLength(JSON.stringify(value))>65536)throw Error('来源校验说明超过限制');scope.manifest[key]=value}
export async function withRawArchive<T>(reservedBytes:number,work:()=>Promise<T>,options:{root?:string}={}):Promise<T>{const scope:RawContext={root:options.root||intelligenceArtifactRoot(),reservedBytes,manifest:{},aborts:new Set()};try{return await context.run(scope,work)}finally{for(const handler of scope.aborts){try{handler(Error('来源处理已结束'))}catch{}}await scope.writer?.abort()}}
export async function withNestedRawArchive<T>(reservedBytes:number,work:()=>Promise<T>):Promise<T>{
 const parent=currentRawArchive();if(!parent||!Number.isSafeInteger(reservedBytes)||reservedBytes<1||reservedBytes>parent.reservedBytes)throw Error('分段原件预算超过本次任务预留');if(parent.cancelled)throw parent.cancelled;
 let abortChild:((error:Error)=>void)|undefined;const detach=onSourceAbort(error=>abortChild?.(error));
 try{return await withRawArchive(reservedBytes,async()=>{abortChild=AsyncResource.bind(cancelRawSource);if(parent.cancelled)cancelRawSource(parent.cancelled);const child=currentRawArchive()!;if(child.cancelled)throw child.cancelled;return work()},{root:parent.root})}finally{detach()}
}
export async function* captureRawChunks(chunks:AsyncIterable<Uint8Array>,encoding:RawArtifact['encoding']='GZIP_JSON'):AsyncGenerator<Uint8Array>{
 const scope=context.getStore();if(!scope){yield* chunks;return}if(scope.writer)throw Error('一次快照不能混合多个原始数据包');const writer=scope.writer=await rawWriter(scope,encoding);let complete=false;
 try{for await(const part of chunks){await writer.write(part);yield part}scope.artifact=await writer.finish();complete=true}finally{if(!complete)await writer.abort()}
}
export async function captureRawBuffer(bytes:Buffer,encoding:RawArtifact['encoding']='GZIP_JSON'){async function* chunks(){yield bytes}for await(const _ of captureRawChunks(chunks(),encoding)){}}
export async function intelligenceArtifactUsage(root=intelligenceArtifactRoot()){
 await ensure(root);let bytes=0,objects=0,partialBytes=0;
 for(const directory of ['objects','tmp'])for(const name of await readdir(join(root,directory))){const info=await lstat(join(root,directory,name));if(info.isFile()){bytes+=info.size;if(directory==='objects')objects++;else partialBytes+=info.size}}
 return {bytes,objects,partialBytes};
}
export async function intelligenceArtifactQuota(tx:any){const policy=(await tx.setting.findUnique({where:{key:'storage-policy'}}))?.value as any;const bytes=Number(process.env.INTELLIGENCE_ARTIFACT_QUOTA_BYTES||(policy?.intelligenceArtifactQuotaGiB||5)*1024**3);if(!Number.isSafeInteger(bytes)||bytes<1024**2||bytes>1024**4)throw Error('原始数据空间上限配置无效');return bytes}
export async function reserveIntelligenceArtifact(tx:any,added:number){
 await tx.$queryRaw`SELECT pg_advisory_xact_lock(hashtext('selfguard-intelligence-artifacts'))::text`;const usage=await intelligenceArtifactUsage(),reserved=await tx.vulnerabilitySnapshot.aggregate({where:{status:'STAGING'},_sum:{reservedArtifactBytes:true}}),limit=await intelligenceArtifactQuota(tx);
 if(usage.bytes+(reserved._sum.reservedArtifactBytes||0)+added>limit)throw new HttpException('原始情报空间上限不足，未开始替换快照；请调整存储上限或清理已确认不再需要的文件',507);
 return {...usage,reservedBytes:reserved._sum.reservedArtifactBytes||0,limit};
}
export async function registerIntelligenceArtifact(tx:any,sourceSha256:string){
 const artifact=context.getStore()?.artifact;if(!artifact)return null;if(artifact.payloadSha256!==sourceSha256)throw Error('原始数据与来源摘要不一致，未发布快照');await tx.$queryRaw`SELECT pg_advisory_xact_lock(hashtext('selfguard-intelligence-artifacts'))::text`;
 const row=await tx.intelligenceArtifact.upsert({where:{sha256:artifact.sha256},create:{sha256:artifact.sha256,size:artifact.size,encoding:artifact.encoding},update:{}});if(row.size!==artifact.size||row.encoding!==artifact.encoding)throw Error('原始制品元数据冲突');return row;
}
