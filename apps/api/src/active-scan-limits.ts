import {ConflictException} from '@nestjs/common';
import {z} from 'zod';
import {compatibleProbe} from './scan-network-contracts';
const limit=z.number().int().min(1).max(10000);
type Template={definition:{kind?:string;protocol?:string;rule?:{nativeTemplate?:unknown;maxRedirects?:number}}};
export function previewRequestLimit(endpoints:{assetId:string;protocol:string}[],templates:Template[],previous?:{requestLimit?:number}){
 if(previous)return previous.requestLimit;
 if(!templates.some(t=>t.definition.rule?.nativeTemplate))return undefined;
 const byAsset=new Map<string,number>();
 for(const endpoint of endpoints){const upper=templates.reduce((sum,t)=>sum+(!compatibleProbe(t.definition,endpoint.protocol)?0:t.definition.kind==='NETWORK'?1:1+(t.definition.rule?.maxRedirects??3)),0);byAsset.set(endpoint.assetId,(byAsset.get(endpoint.assetId)||0)+upper)}
 const maximum=Math.max(300,...byAsset.values());if(maximum>10000)throw new ConflictException('本次每台主机请求上界超过10000，请缩小入口或规则范围');return maximum>300?maximum:undefined;
}
export function frozenRequestLimit(inventory:unknown){const value=z.object({activeSources:z.object({requestLimit:limit.optional()}).passthrough()}).passthrough().parse(inventory);return value.activeSources.requestLimit??300}

export function assertActiveSelectionBudget(templates:Template[],endpoints:unknown[],assetCount:number,checks:number){
 if(checks>10000)throw new ConflictException('本次检查组合超过10000项，请缩小目标或规则范围');
 if(!templates.some(t=>t.definition.rule?.nativeTemplate))return;
 const bytes=Buffer.byteLength(JSON.stringify({definitions:templates.map(t=>t.definition),endpoints}));
 if(bytes>16*1024*1024||bytes*Math.max(1,assetCount)>64*1024*1024)throw new ConflictException('本次冻结规则与范围数据超过内存预算，请缩小目标或规则范围');
}
