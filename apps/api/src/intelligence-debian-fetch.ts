import {jsonObjectPairs} from './intelligence-json-stream';import {openOfficialStream} from './intelligence-stream-fetch';
export type DebianStream={entries:AsyncIterable<[string,unknown]>;abort:()=>void};
export async function fetchDebianTracker(url:URL):Promise<{document:DebianStream;sourceSha256:string}>{
 if(url.href!=='https://security-tracker.debian.org/tracker/data/json')throw Error('Debian来源地址不在允许范围');
 const stream=await openOfficialStream(url,'HTTP_JSON');
 async function* entries():AsyncGenerator<[string,unknown]>{for await(const [[name,identity],raw]of jsonObjectPairs(stream.chunks))yield [name,{[identity]:raw}]}
 return {document:{entries:entries(),abort:stream.abort},get sourceSha256(){return stream.sourceSha256}};
}
export function isDebianStream(value:any):value is DebianStream{return typeof value?.entries?.[Symbol.asyncIterator]==='function'&&typeof value.abort==='function'}
