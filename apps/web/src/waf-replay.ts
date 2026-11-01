export function wafReplayOutcome(result:{blocked:boolean;incomplete?:string[]}){
 if(result.incomplete?.length)return {type:'warning' as const,title:'样本检查不完整，请核对异常编码或解析限制'};
 return result.blocked?{type:'warning' as const,title:'样本判定：达到阻断条件'}:{type:'success' as const,title:'样本判定：未达到阻断条件'};
}

export function wafEventTitle(record:any){
 if(record.title)return record.title;
 const rules:Record<string,string>={SQLI:'SQL注入特征',XSS:'跨站脚本特征',TRAVERSAL:'目录穿越特征',COMMAND:'命令注入特征',IP:'来源访问限制',METHOD:'非允许请求方法',PATH:'受限路径访问',RATE:'访问频率超限',ENCODING:'正文编码无法检查',INSPECTION_INCOMPLETE:'规则检查未完成'};
 const message=Array.isArray(record.inspection?.evidence)?record.inspection.evidence.find((item:any)=>typeof item?.messageTemplate==='string'&&item.messageTemplate.trim())?.messageTemplate:undefined;
 const rule=message||(Object.hasOwn(rules,record.ruleId)?rules[record.ruleId]:/^\d+$/.test(record.ruleId||'')?'防护规则 '+record.ruleId:'自定义防护规则命中');
 return rule+' · '+(record.inspection&&typeof record.inspection==='object'&&record.inspection.siteHostname||'站点攻击记录');
}

export function wafAccessTitle(record:any){
 const path=record.path&&record.path!=='[redacted]'&&record.path!=='[已隐藏]'?record.path:'访问记录';
 return `${record.method||'HTTP'} ${path} · ${record.status===undefined?'响应状态未留存':'HTTP '+record.status}`;
}
