import type {request} from 'node:https';
import {osvModifiedNanoseconds as sourceNanoseconds} from './intelligence-osv-index';
import {z} from 'zod';import {openOfficialStream,type OfficialByteStream} from './intelligence-stream-fetch';import {jsonArrayFeed} from './intelligence-array-stream';
import {recordSourceManifest} from './intelligence-artifacts';
export function nvdTimeNanoseconds(value:string){const explicit=/(?:Z|[+-]\d{2}:\d{2})$/.test(value);return sourceNanoseconds(explicit?value:value+'Z')}
export function parseNvdMeta(text:string){
 const values:Record<string,string>={};for(const line of text.split(/\r?\n/).filter(Boolean)){const colon=line.indexOf(':');if(colon<1)throw Error('NVD元数据行无效');const key=line.slice(0,colon),value=line.slice(colon+1);if(Object.hasOwn(values,key))throw Error('NVD元数据字段重复');values[key]=value}
 const size=z.coerce.number().int().min(1).max(1024*1024*1024).parse(values.size),gzSize=z.coerce.number().int().min(1).max(128*1024*1024).parse(values.gzSize),sha256=z.string().regex(/^[a-fA-F0-9]{64}$/).parse(values.sha256).toLowerCase(),lastModifiedDate=z.string().max(100).parse(values.lastModifiedDate);try{nvdTimeNanoseconds(lastModifiedDate)}catch{throw Error('NVD元数据修改时间无效')}return {size,gzSize,sha256,lastModifiedDate};
}
export type NvdFeedStream={kind:'NVD_FEED_STREAM';scope:'ANNUAL'|'MODIFIED';readonly generatedAt?:string;readonly recordsRead?:number;entries:AsyncIterable<unknown>;meta:ReturnType<typeof parseNvdMeta>;validate:()=>void;abort:()=>void};
export async function fetchNvdAnnualFeed(url:URL,transport?:typeof request):Promise<{document:NvdFeedStream;sourceSha256:string}>{
 if(url.origin!=='https://nvd.nist.gov'||!/^\/feeds\/json\/cve\/2\.0\/nvdcve-2\.0-\d{4}\.json\.gz$/.test(url.pathname)||url.search||url.hash)throw Error('NVD年度源地址无效');
 return fetchNvdFixedFeed(url,'ANNUAL',transport);
}
export function fetchNvdModifiedFeed(transport?:typeof request){return fetchNvdFixedFeed(new URL('https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-modified.json.gz'),'MODIFIED',transport)}
export function fetchNvdModifiedMeta(transport?:typeof request){return fetchNvdMeta(new URL('https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-modified.json.gz'),transport)}
async function fetchNvdFixedFeed(url:URL,scope:NvdFeedStream['scope'],transport?:typeof request){const meta=await fetchNvdMeta(url,transport);return nvdFeedDocument(meta,await openOfficialStream(url,'GZIP_FILE',transport),scope)}
async function fetchNvdMeta(url:URL,transport?:typeof request){
 const metaStream=await openOfficialStream(new URL(url.href.replace(/\.json\.gz$/,'.meta')),'TEXT',transport);let text='';try{const decoder=new TextDecoder('utf-8',{fatal:true});for await(const chunk of metaStream.chunks)text+=decoder.decode(chunk,{stream:true});text+=decoder.decode()}finally{metaStream.abort()}
 const meta=parseNvdMeta(text);recordSourceManifest('nvdMeta',{...meta,original:text,sha256OfMeta:metaStream.sourceSha256});return meta;
}
export function nvdFeedDocument(meta:ReturnType<typeof parseNvdMeta>,stream:OfficialByteStream,scope:NvdFeedStream['scope']='ANNUAL',retainManifest=true):{document:NvdFeedStream;sourceSha256:string}{
 const header:Record<string,unknown>={};let count=0,finished=false;const ids=new Set<string>();
 async function* entries(){for await(const item of jsonArrayFeed(stream.chunks,'vulnerabilities')){if('record'in item){const id=(item.record as any)?.cve?.id;if(typeof id!=='string'||!/^CVE-\d{4}-\d{4,}$/.test(id)||ids.has(id))throw Error('NVD通告编号无效或重复');ids.add(id);count++;if(count>250000)throw Error('年度NVD超过25万通告限制');yield item.record}else header[item.key]=item.value}finished=true}
 function validate(){if(!finished||stream.sourceSha256!==meta.sha256||stream.decodedBytes!==meta.size)throw Error('NVD官方摘要或字节数不一致，未发布年度快照');if(header.format!=='NVD_CVE'||header.version!=='2.0'||header.startIndex!==0||header.totalResults!==count||header.resultsPerPage!==count)throw Error('NVD年度元数据数量或格式不完整');if(typeof header.timestamp!=='string')throw Error('NVD来源生成时间无效');nvdTimeNanoseconds(header.timestamp);if(retainManifest)recordSourceManifest('nvdFeed',{scope,generatedAt:header.timestamp,records:count})}
 return {document:{kind:'NVD_FEED_STREAM',scope,get recordsRead(){return count},get generatedAt(){return typeof header.timestamp==='string'?header.timestamp:undefined},entries:entries(),meta,validate,abort:stream.abort},get sourceSha256(){return stream.sourceSha256}};
}
export function isNvdFeedStream(value:any):value is NvdFeedStream{return value?.kind==='NVD_FEED_STREAM'&&typeof value?.entries?.[Symbol.asyncIterator]==='function'&&typeof value.validate==='function'&&typeof value.abort==='function'}
