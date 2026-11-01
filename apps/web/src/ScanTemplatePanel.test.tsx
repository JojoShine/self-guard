import {it,expect,vi} from 'vitest';vi.mock('./api',()=>({api:vi.fn()}));import {templateFormValue,templatePayload} from './ScanTemplatePanel';
it('keeps finite choices and converts readable sample header rows without losing duplicate headers',()=>{
 const data={name:'测试',purpose:'CONFIGURATION',severity:'LOW',description:'明确依据',remediation:'修改后复测',method:'GET',path:'/',operator:'ALL',conditions:[{kind:'STATUS',status:200,value:'stale',header:'stale'},{kind:'HEADER_MISSING',header:'X-Frame-Options',value:'stale'}],samples:[{name:'命中',expectedMatched:true,status:200,headers:{'X-Test':['one','two'],constructor:['safe']},body:'actual'}]};
 const payload=templatePayload(templateFormValue(data));expect(payload.conditions).toEqual([{kind:'STATUS',status:200},{kind:'HEADER_MISSING',header:'X-Frame-Options'}]);expect(payload.samples[0].headers).toEqual({'X-Test':['one','two'],constructor:['safe']});expect(payload.samples[0].expectedMatched).toBe(true);
});

it('round-trips matcher groups, individual negation and explicit no-redirect settings',()=>{
 const value={name:'Grouped rule',description:'Native grouped conditions',remediation:'Review',purpose:'EXPOSURE',severity:'LOW',method:'GET',path:'/',operator:'ALL',maxRedirects:0,groups:[{operator:'ANY',negative:true,conditions:[{kind:'BODY_CONTAINS',value:'html'},{kind:'BODY_REGEX',value:'(?i)<body',negative:true}]}],samples:[]};
 const result=templatePayload(templateFormValue(value));expect(result.groups).toEqual(value.groups);expect(result.maxRedirects).toBe(0);expect(result).not.toHaveProperty('conditions');expect(result).not.toHaveProperty('conditionLayout');
});

it('round-trips exact source text transforms, byte comparisons and redacted extractors',()=>{
 const value={name:'Source semantics',description:'Exact',remediation:'Review',purpose:'EXPOSURE',severity:'LOW',method:'GET',path:'/',operator:'ALL',conditions:[{kind:'BODY_LENGTH',comparison:'GT',threshold:50,value:'stale'},{kind:'HEADER_LOWER_CONTAINS',header:'Content-Type',value:'text/html',negative:true},{kind:'BODY_FOLD_CONTAINS',value:'Marker'}],extractors:[{kind:'BODY_REGEX',value:'key=(.*)',group:1,name:'key format'}],samples:[]};
 const result=templatePayload(templateFormValue(value));expect(result.conditions).toEqual(value.conditions.map(({value:old,...row},i)=>i===0?row:{...row,value:old}));expect(result.extractors).toEqual(value.extractors);
});

it('preserves explicit redirect response semantics instead of replacing them with the final page',()=>{
 const value={name:'Redirect source',description:'Precise chain matching',remediation:'Review',purpose:'EXPOSURE',severity:'LOW',method:'GET',path:'/start',operator:'ALL',responseMode:'ANY_REDIRECT',maxRedirects:10,conditions:[{kind:'STATUS',status:302}],samples:[]};const payload=templatePayload(templateFormValue(value));expect(payload.responseMode).toBe('ANY_REDIRECT');expect(payload.maxRedirects).toBe(10);
});

it('round-trips network certificate samples without HTTP fields or stale disconnected observations',()=>{
 const value={kind:'NETWORK',protocol:'tls',checkKind:'TLS_CERT_EXPIRED',name:'证书到期检查',purpose:'CONFIGURATION',severity:'MEDIUM',description:'核对实际证书时间',remediation:'更新证书后复查',samples:[{name:'已过期',expectedMatched:true,connected:true,tlsVersion:'TLS1.3',observedAt:'2026-11-01T00:00:00Z',notBefore:'2026-10-01T00:00:00Z',notAfter:'2026-10-31T00:00:00Z'},{name:'未连接',expectedMatched:false,connected:false}]};
 const fields=templateFormValue(value);expect(fields.samples[0].connected).toBe('CONNECTED');expect(fields.samples[1].connected).toBe('DISCONNECTED');fields.samples[1].tlsVersion='TLS1.0';fields.samples[1].notAfter='2020-01-01T00:00:00Z';const payload=templatePayload(fields);expect(payload.samples[1]).toEqual({name:'未连接',expectedMatched:false,connected:false});expect(payload.samples[0]).toEqual({...value.samples[0],observedAt:'2026-11-01T00:00:00.000Z',notBefore:'2026-10-01T00:00:00.000Z',notAfter:'2026-10-31T00:00:00.000Z'});for(const field of ['method','path','conditions','groups','operator','maxRedirects','responseMode'])expect(payload).not.toHaveProperty(field);
});
it('keeps network marker bytes literal and clears irrelevant rule parameters when changing check kind',()=>{
 const value={kind:'NETWORK',protocol:'tcp',checkKind:'TCP_BANNER',name:'服务特征',purpose:'CONFIGURATION',severity:'LOW',description:'明确内容',remediation:'核对后升级',matchValue:' legacy ',days:30,samples:[{name:'命中',expectedMatched:true,connected:true,banner:'owned legacy service\r\n'},{name:'反例',expectedMatched:false,connected:true,banner:'normal\r\n'}]};const form=templateFormValue(value),payload=templatePayload(form);expect(payload.matchValue).toBe(' legacy ');expect(payload.days).toBe(0);const observed=templatePayload({...form,checkKind:'TCP_CONNECT',purpose:'OBSERVATION',severity:'INFO'});expect(observed.matchValue).toBe('');expect(observed.samples[0]).not.toHaveProperty('banner');
});
