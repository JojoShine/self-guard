import {ConflictException,ServiceUnavailableException} from '@nestjs/common';import {spawn} from 'node:child_process';import {z} from 'zod';
import {networkDefinition,networkSamples} from './scan-network-contracts';import {readProbeFrames} from './scan-worker';
const evaluation=z.object({kind:z.literal('NETWORK_RULE_RESULT'),result:z.object({matched:z.boolean(),observation:z.boolean()}).strict()}).strict();
export async function validateNetworkSamples(input:unknown,samples:unknown){
 const definition=networkDefinition.safeParse(input),parsed=networkSamples.safeParse(samples);if(!definition.success||!parsed.success)throw new ConflictException('网络检查与样本无效：选择明确TCP/TLS检查，并提供应命中和应不命中的完整观察样本');
 const results:Array<{name:string;expectedMatched:boolean;actualMatched:boolean;observation:boolean;passed:boolean}>=[];
 for(const {name,expectedMatched,...sample}of parsed.data){
  const child=spawn(process.env.SCAN_WORKER_BINARY||'/opt/selfguard/scanner',[],{stdio:['pipe','pipe','pipe'],env:{PATH:'/usr/local/bin:/usr/bin:/bin',GOMEMLIMIT:'128MiB'},windowsHide:true});let unavailable=false,timedOut=false;child.once('error',()=>{unavailable=true});child.stdin.on('error',()=>{});child.stderr.on('data',()=>{});const closed=new Promise<number|null>(resolve=>child.once('close',resolve)),timer=setTimeout(()=>{timedOut=true;child.kill('SIGKILL')},2500);timer.unref();
  try{
   child.stdin.end(JSON.stringify({kind:'CHECK_NETWORK_RULE',networkRule:definition.data.rule,networkSample:sample})+'\n');let result:z.infer<typeof evaluation>['result']|undefined;for await(const frame of readProbeFrames(child.stdout)){if(result)throw Error('extra offline observation');result=evaluation.parse(frame).result}
   const code=await closed;if(unavailable||timedOut)throw new ServiceUnavailableException('网络规则校验程序不可用或超时，尚未批准规则');if(code!==0||!result||result.observation!==['TCP_CONNECT','TLS_HANDSHAKE'].includes(definition.data.rule.kind))throw new ConflictException('网络样本不完整或与检查类型不匹配，请核对连接、服务特征、TLS版本及证书日期');results.push({name,expectedMatched,actualMatched:result.matched,observation:result.observation,passed:expectedMatched===result.matched});
  }catch(error){child.kill('SIGKILL');await closed;if(error instanceof ConflictException||error instanceof ServiceUnavailableException)throw error;throw new ServiceUnavailableException('网络规则校验结果不完整，尚未批准规则')}
  finally{clearTimeout(timer);child.stdin.destroy()}
 }
 return {engineVersion:'selfguard-network-v1',passed:results.every(row=>row.passed),samples:results,meaning:'仅验证明确提供的离线连接与证书样本，不请求目标，不把样本当作资产风险证据。连通和握手条件即使命中也仅形成观察结果。'};
}
