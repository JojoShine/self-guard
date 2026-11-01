import {ConflictException,ServiceUnavailableException} from '@nestjs/common';import {spawn} from 'node:child_process';import {z} from 'zod';import {probeRule,readProbeFrames} from './scan-worker';
export const probeDefinition=z.object({method:z.enum(['GET','HEAD']),path:z.string().min(1).max(2048).regex(/^\/[^?#%\\]*$/).refine(value=>!value.split('/').some(part=>part==='.'||part==='..'),'使用明确的只读路径，不包含回退目录或编码分隔符'),rule:probeRule}).strict();
export const probeSample=z.object({name:z.string().trim().min(1).max(100),expectedMatched:z.boolean(),status:z.number().int().min(100).max(599),headers:z.record(z.string().min(1).max(200),z.array(z.string().max(4096)).max(8)).refine(value=>Object.keys(value).length<=100).default({}),body:z.string().max(65536).default('')}).strict();
export const probeSamples=z.array(probeSample).min(2).max(8).refine(values=>values.some(x=>x.expectedMatched)&&values.some(x=>!x.expectedMatched),'至少提供一个应命中样本和一个应不命中样本');
const sampleCondition=z.object({condition:z.unknown(),matched:z.boolean()}).strict(),sampleGroup=z.object({name:z.string().max(200).optional(),operator:z.enum(['ALL','ANY']),negative:z.boolean().optional(),matched:z.boolean(),conditions:z.array(sampleCondition).min(1).max(32)}).strict();
const evaluation=z.object({kind:z.literal('RULE_RESULT'),result:z.object({matched:z.boolean(),conditions:z.array(sampleCondition).max(32),groups:z.array(sampleGroup).max(32).optional()}).strict()}).strict();
export async function validateRuleSamples(input:unknown,samples:unknown){
 const definition=probeDefinition.safeParse(input),parsed=probeSamples.safeParse(samples);if(!definition.success||!parsed.success)throw new ConflictException('规则和样本无效：选择GET或HEAD、明确路径，并提供应命中和应不命中的完整响应样本');
 const results:Array<{name:string;expectedMatched:boolean;actualMatched:boolean;passed:boolean;conditions:z.infer<typeof evaluation>['result']['conditions'];groups?:z.infer<typeof evaluation>['result']['groups']}>=[];
 for(const sample of parsed.data){
  const {name,expectedMatched,...response}=sample,child=spawn(process.env.SCAN_WORKER_BINARY||'/opt/selfguard/scanner',[],{stdio:['pipe','pipe','pipe'],env:{PATH:'/usr/local/bin:/usr/bin:/bin',GOMEMLIMIT:'128MiB'},windowsHide:true});let unavailable=false,timedOut=false;child.once('error',()=>{unavailable=true});child.stdin.on('error',()=>{});child.stderr.on('data',()=>{});const closed=new Promise<number|null>(resolve=>child.once('close',resolve)),timer=setTimeout(()=>{timedOut=true;child.kill('SIGKILL')},2500);timer.unref();
  try{
   child.stdin.end(JSON.stringify({kind:'CHECK_RULE',method:definition.data.method,rule:definition.data.rule,sample:response})+'\n');let result:z.infer<typeof evaluation>['result']|undefined;for await(const frame of readProbeFrames(child.stdout)){if(result)throw Error('extra offline result');result=evaluation.parse(frame).result}
   const code=await closed;if(unavailable||timedOut)throw new ServiceUnavailableException('规则校验程序不可用或超时，未批准规则');if(code!==0||!result||result.conditions.length!==(definition.data.rule.conditions?.length||0)||(result.groups?.length||0)!==(definition.data.rule.groups?.length||0))throw new ConflictException('规则或样本不受支持，请检查请求方式、响应头、正文条件和正则表达式；尚未通过校验');
   results.push({name,expectedMatched,actualMatched:result.matched,passed:expectedMatched===result.matched,conditions:result.conditions,...(result.groups?{groups:result.groups}:{})});
  }catch(error){child.kill('SIGKILL');await closed;if(error instanceof ConflictException||error instanceof ServiceUnavailableException)throw error;throw new ServiceUnavailableException('规则校验结果不完整，未批准规则')}
  finally{clearTimeout(timer);child.stdin.destroy()}
 }
 return {engineVersion:'selfguard-probe-v1',passed:results.every(row=>row.passed),samples:results,meaning:'仅核对明确提供的离线响应样本，没有请求目标；样本通过不等于真实资产存在漏洞。'};
}
