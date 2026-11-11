import {Agent,request as httpsRequest} from 'node:https';import {request as httpRequest} from 'node:http';import {lookup} from 'node:dns/promises';import {connect as tlsConnect} from 'node:tls';import {publicAddress} from './advisories';import {isIP} from 'node:net';import {z} from 'zod';
type Resolver=(host:string)=>Promise<Array<{address:string;family:number}>>;
export function sourceProxyAgent(target:URL,setting=process.env.INTELLIGENCE_HTTPS_PROXY||'',resolve?:Resolver):Agent|false{
 if(!setting)return false;
 let proxy:URL;try{proxy=new URL(setting)}catch{throw Error('来源代理地址无效')}
 if(!['http:','https:'].includes(proxy.protocol)||proxy.pathname!=='/'||proxy.search||proxy.hash||setting.length>4096)throw Error('来源代理必须为明确的HTTP或HTTPS连接代理');
 if(target.protocol!=='https:'||target.port&&target.port!=='443')throw Error('来源代理只连接HTTPS标准端口');
 const agent=new Agent({keepAlive:false,maxSockets:1});
 agent.createConnection=((options:any,callback:any)=>{
  let called=false;const finish=(error?:Error,socket?:any)=>{if(called)return;called=true;callback(error,socket)};
  void (async()=>{
   const addresses=await (resolve?resolve(target.hostname):resolveSourceAddresses(target.hostname,setting));if(!addresses.length||addresses.some(row=>!publicAddress(row.address)))throw Error('来源DNS指向非公开地址，代理连接已拒绝');
   const chosen=addresses.find(row=>row.family===4)||addresses[0],authority=(chosen.family===6?'['+chosen.address+']':chosen.address)+':443';
   const headers:Record<string,string>={host:authority};if(proxy.username||proxy.password)headers['proxy-authorization']='Basic '+Buffer.from(decodeURIComponent(proxy.username)+':'+decodeURIComponent(proxy.password)).toString('base64');
   const request=(proxy.protocol==='https:'?httpsRequest:httpRequest)({protocol:proxy.protocol,hostname:proxy.hostname,port:proxy.port||undefined,method:'CONNECT',path:authority,headers,agent:false,rejectUnauthorized:true,maxHeaderSize:16384});
   request.setTimeout(15000,()=>request.destroy(Error('来源代理连接超过15秒')));request.once('error',error=>finish(error));
   request.once('connect',(response,socket,head)=>{
    if(response.statusCode!==200||head.length){socket.destroy();finish(Error('来源代理未建立有效连接'));return}
    // The CONNECT endpoint is a previously validated literal address. TLS still
    // verifies the official hostname against the normal trust store (or the
    // caller's explicitly supplied CA); a proxy cannot replace that identity.
    const secure=tlsConnect({socket,servername:target.hostname,rejectUnauthorized:true,ca:options.ca,minVersion:'TLSv1.2',ALPNProtocols:['http/1.1']});
    secure.setTimeout(15000,()=>secure.destroy(Error('来源TLS连接超时')));secure.once('error',error=>finish(error));secure.once('secureConnect',()=>{secure.setTimeout(0);finish(undefined,secure)});
   });request.end();
  })().catch(error=>finish(error instanceof Error?error:Error('来源代理连接失败')));
  return undefined;
 }) as any;
 return agent;
}


const dnsReply=z.object({Status:z.literal(0),Question:z.array(z.object({name:z.string().max(254),type:z.literal(1)})).length(1),Answer:z.array(z.object({name:z.string().max(254),type:z.number().int(),TTL:z.number().int().min(0).max(2147483647),data:z.string().max(254)})).min(1).max(64)});
export function parseSourceDnsAnswer(host:string,raw:unknown){
 const r=dnsReply.parse(raw),canonical=(s:string)=>s.toLowerCase().replace(/\.$/,''),name=canonical(host);if(canonical(r.Question[0].name)!==name)throw Error('来源HTTPS DNS问题与请求不符');
 const names=new Set([name]);for(let i=0;i<8;i++)for(const a of r.Answer)if(a.type===5&&names.has(canonical(a.name))&&/^[a-z0-9.-]+\.?$/i.test(a.data))names.add(canonical(a.data));
 const answers=r.Answer.filter(a=>a.type===1);if(!answers.length||answers.some(a=>!names.has(canonical(a.name))||isIP(a.data)!==4||!publicAddress(a.data)))throw Error('来源HTTPS DNS未返回可信公开IPv4地址');
 return{addresses:[...new Set(answers.map(a=>a.data))].map(address=>({address,family:4})),ttl:Math.max(1,Math.min(300,...r.Answer.map(a=>a.TTL)))};
}
const dnsCache=new Map<string,{until:number;addresses:Awaited<ReturnType<Resolver>>}>(),dnsPending=new Map<string,Promise<Awaited<ReturnType<Resolver>>>>();
async function resolveSourceAddresses(host:string,proxy:string):Promise<Awaited<ReturnType<Resolver>>>{
 const enabled=process.env.INTELLIGENCE_PROXY_DNS_OVER_HTTPS||'false';if(!['true','false'].includes(enabled))throw Error('来源代理HTTPS DNS开关无效');if(enabled!=='true')return lookup(host,{all:true,verbatim:true});
 if(!/^[a-z0-9.-]{1,253}$/i.test(host)||isIP(host))throw Error('来源HTTPS DNS只接受明确域名');const key=proxy+'|'+host,hit=dnsCache.get(key);if(hit&&hit.until>Date.now())return hit.addresses;if(dnsPending.has(key))return dnsPending.get(key)!;if(dnsPending.size>=64)throw Error('来源HTTPS DNS并发预算已满');
 const task=new Promise<Awaited<ReturnType<Resolver>>>((resolve,reject)=>{
  // Bootstrap a fixed public resolver through the already configured proxy.
  // The ordinary CONNECT and TLS hostname checks remain active for both hops.
  const target=new URL('https://cloudflare-dns.com/dns-query');target.searchParams.set('name',host);target.searchParams.set('type','A');const agent=sourceProxyAgent(target,proxy,async()=>[{address:'1.1.1.1',family:4}]);
  let settled=false;const chunks:Buffer[]=[];let bytes=0;const finish=(error?:Error,value?:ReturnType<typeof parseSourceDnsAnswer>)=>{if(settled)return;settled=true;clearTimeout(timer);if(agent)agent.destroy();if(error)reject(error);else{if(dnsCache.size>=64)dnsCache.delete(dnsCache.keys().next().value!);dnsCache.set(key,{until:Date.now()+value!.ttl*1000,addresses:value!.addresses});resolve(value!.addresses)}};
  const request=httpsRequest(target,{agent,rejectUnauthorized:true,maxHeaderSize:16384,headers:{accept:'application/dns-json'}},response=>{if(response.statusCode!==200||!String(response.headers['content-type']||'').toLowerCase().includes('application/dns-json')){response.resume();finish(Error('来源HTTPS DNS响应无效'));return}response.on('data',(part:Buffer)=>{bytes+=part.length;if(bytes>65536){response.destroy();finish(Error('来源HTTPS DNS响应超过64KiB预算'));return}chunks.push(Buffer.from(part))});response.once('aborted',()=>finish(Error('来源HTTPS DNS响应中断')));response.once('error',()=>finish(Error('来源HTTPS DNS读取失败')));response.once('end',()=>{try{finish(undefined,parseSourceDnsAnswer(host,JSON.parse(Buffer.concat(chunks).toString('utf8'))))}catch{finish(Error('来源HTTPS DNS内容或公开地址校验失败'))}})});
  const timer=setTimeout(()=>{request.destroy();finish(Error('来源HTTPS DNS超过12秒预算'))},12000);timer.unref();request.once('error',()=>finish(Error('来源HTTPS DNS连接失败')));request.end();
 });dnsPending.set(key,task);try{return await task}finally{dnsPending.delete(key)}
}
