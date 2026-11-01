import {Agent,request as httpsRequest} from 'node:https';import {request as httpRequest} from 'node:http';import {lookup} from 'node:dns/promises';import {connect as tlsConnect} from 'node:tls';import {publicAddress} from './advisories';
type Resolver=(host:string)=>Promise<Array<{address:string;family:number}>>;
export function sourceProxyAgent(target:URL,setting=process.env.INTELLIGENCE_HTTPS_PROXY||'',resolve:Resolver=host=>lookup(host,{all:true,verbatim:true})):Agent|false{
 if(!setting)return false;
 let proxy:URL;try{proxy=new URL(setting)}catch{throw Error('来源代理地址无效')}
 if(!['http:','https:'].includes(proxy.protocol)||proxy.pathname!=='/'||proxy.search||proxy.hash||setting.length>4096)throw Error('来源代理必须为明确的HTTP或HTTPS连接代理');
 if(target.protocol!=='https:'||target.port&&target.port!=='443')throw Error('来源代理只连接HTTPS标准端口');
 const agent=new Agent({keepAlive:false,maxSockets:1});
 agent.createConnection=((options:any,callback:any)=>{
  let called=false;const finish=(error?:Error,socket?:any)=>{if(called)return;called=true;callback(error,socket)};
  void (async()=>{
   const addresses=await resolve(target.hostname);if(!addresses.length||addresses.some(row=>!publicAddress(row.address)))throw Error('来源DNS指向非公开地址，代理连接已拒绝');
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
