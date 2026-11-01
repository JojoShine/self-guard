import {test} from 'node:test';import assert from 'node:assert/strict';import {PassThrough} from 'node:stream';import {EventEmitter} from 'node:events';import {createHash} from 'node:crypto';
import {openUbuntuArchive} from '../src/intelligence-range-fetch';import {withRawArchive,cancelRawSource} from '../src/intelligence-artifacts';
const url=new URL('https://storage.googleapis.com/osv-vulnerabilities/Ubuntu/all.zip');
function transport(bytes:Buffer,alter?:(response:any,probe:boolean)=>void){
 let active=0,peak=0,requests=0,destroyed=0;
 const request:any=(_url:any,options:any,callback:any)=>{
  const request:any=new EventEmitter();let response:any,settled=false;
  request.destroy=(error?:Error)=>{if(!settled){settled=true;destroyed++;active--;response?.destroy();queueMicrotask(()=>request.emit('error',error||Error('cancelled')))}return request};
  request.end=()=>{requests++;const match=/^bytes=(\d+)-(\d+)$/.exec(options.headers.Range);assert.ok(match);const start=Number(match[1]),end=Number(match[2]),probe=start===0&&end===0;assert.ok(end-start+1<=8*1024*1024);if(!probe)assert.equal(options.headers['x-goog-if-generation-match'],'123456789');active++;peak=Math.max(peak,active);
   queueMicrotask(()=>{response=new PassThrough();response.statusCode=206;response.headers={'content-range':`bytes ${start}-${end}/${bytes.length}`,'x-goog-generation':'123456789','x-goog-hash':'crc32c=AAAAAA=='};alter?.(response,probe);callback(response);setImmediate(()=>{if(settled)return;if(response.hang)return;settled=true;active--;response.end(bytes.subarray(start,end+1))})})
  };return request;
 };return {request,stats:()=>({peak,requests,destroyed})};
}

test('a pinned official archive is read in order with bounded parallel ranges and full byte hashing',async()=>{
 const bytes=Buffer.alloc(24*1024*1024+7,0x61),mock=transport(bytes);
 const stream=await openUbuntuArchive(url,mock.request),parts=[];for await(const part of stream.chunks)parts.push(Buffer.from(part));assert.deepEqual(Buffer.concat(parts),bytes);assert.equal(stream.sourceSha256,createHash('sha256').update(bytes).digest('hex'));assert.equal(stream.decodedBytes,bytes.length);assert.equal(mock.stats().peak,4);assert.equal(mock.stats().requests,5);
});

test('wrong range, generation changes, ordinary responses and oversized archives cannot be accepted',async()=>{
 for(const alter of [
  (r:any,p:boolean)=>{if(!p)r.headers['content-range']='bytes 1-2/3'},
  (r:any,p:boolean)=>{if(!p)r.headers['x-goog-generation']='another-version'},
  (r:any,p:boolean)=>{if(!p)r.statusCode=200},
  (r:any,p:boolean)=>{if(p)r.headers['content-range']='bytes 0-0/1073741825'},
  (r:any)=>{r.headers['content-encoding']='gzip'},
 ]){const mock=transport(Buffer.from('official-byte-fixture'),alter);await assert.rejects(async()=>{const stream=await openUbuntuArchive(url,mock.request);for await(const _ of stream.chunks){}})}
 await assert.rejects(()=>openUbuntuArchive(new URL('https://127.0.0.1/Ubuntu/all.zip')));
});

test('revocation stops in-flight ranges and cannot produce a completed source hash',async()=>{
 await withRawArchive(1024,async()=>{
  const mock=transport(Buffer.alloc(24*1024*1024+7),(response,probe)=>{if(!probe)response.hang=true}),stream=await openUbuntuArchive(url,mock.request);
  const timer=setTimeout(()=>cancelRawSource(Error('lease revoked fixture')),20);
  try{await assert.rejects(async()=>{for await(const _ of stream.chunks){}},/lease revoked/);assert.equal(stream.sourceSha256,'');assert.equal(mock.stats().destroyed,4)}finally{clearTimeout(timer)}
 });
});

test('source throttling preserves Retry-After for the owning scheduler',async()=>{
 const mock=transport(Buffer.from('fixture'),response=>{response.statusCode=429;response.headers['retry-after']='120'});
 await assert.rejects(()=>openUbuntuArchive(url,mock.request),(error:any)=>error.retryAfterSeconds===120);
});

test('short range bodies and missing checksum metadata cannot finish a source',async()=>{
 const missing=transport(Buffer.from('fixture'),response=>{delete response.headers['x-goog-hash']});await assert.rejects(()=>openUbuntuArchive(url,missing.request),/CRC32C/);
 const short:any=(_url:any,options:any,callback:any)=>{const request:any=new EventEmitter();request.destroy=()=>request;request.end=()=>queueMicrotask(()=>{const response:any=new PassThrough();response.statusCode=206;response.headers={'content-range':'bytes 0-0/20','x-goog-generation':'123456789','x-goog-hash':'crc32c=AAAAAA=='};callback(response);response.end()});return request};
 await assert.rejects(()=>openUbuntuArchive(url,short),/未完整结束/);
});
