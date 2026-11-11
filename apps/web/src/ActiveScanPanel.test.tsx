import {renderToStaticMarkup} from 'react-dom/server';
import {it,expect,vi} from 'vitest';vi.mock('./api',()=>({api:vi.fn()}));import {ScanRequestBudget,activePlanChoices,currentApprovedRuleIds} from './ActiveScanPanel';
it('derives only selected approved endpoint assets and keeps asset and tag exclusions as separate groups',()=>{
 const value=activePlanChoices({endpointIds:['one'],templateIds:['template'],excludeAssets:['b'],excludeTags:['maintenance']},[{id:'one',assetId:'a'},{id:'two',assetId:'other'}]);expect(value.scope.include).toEqual([{assetIds:['a'],types:['SERVICE']}]);expect(value.scope.exclude).toEqual([{assetIds:['b']},{tags:['maintenance']}]);expect(()=>activePlanChoices({endpointIds:['missing'],templateIds:['template']},[])).toThrow('重新选择');
});

it('selects every current compatible approved rule, never a brand or a silent subset',()=>{
 const endpoints=[{id:'web',protocol:'https'},{id:'tcp',protocol:'tcp'}];
 const rules=[{id:'a',protocol:'http'},{id:'b',protocol:'tcp'},{id:'c',protocol:'tls'},{id:'d',protocol:'http'}];
 expect(currentApprovedRuleIds(['web'],endpoints,rules)).toEqual(['a','d']);
 expect(currentApprovedRuleIds(['web','tcp'],endpoints,rules)).toEqual(['a','b','d']);
 expect(()=>currentApprovedRuleIds(['web'],endpoints,Array.from({length:5001},(_,i)=>({id:String(i),protocol:'http'})))).toThrow('5000');
});

it('accepts the API HTTP/HTTPS compatibility label for generic rule selection',()=>{
 expect(currentApprovedRuleIds(['entry'],[{id:'entry',protocol:'https'}],[{id:'official',protocol:'http/https'},{id:'local'},{id:'tcp',protocol:'tcp'}])).toEqual(['official','local']);
});

it('shows the frozen per-asset request limit and preserves the legacy default',()=>{
 const html=renderToStaticMarkup(<ScanRequestBudget requestLimit={640}/>);expect(html).toContain('640');expect(html).toContain('每个资产');expect(html).toContain('共享速率限制保持不变');
 expect(renderToStaticMarkup(<ScanRequestBudget/>)).toContain('300');
});

it('selects the whole compatible corpus without asking ordinary users to split plans',()=>{
 const rules=Array.from({length:2073},(_,i)=>({id:'official-'+i,protocol:'http/https'}));
 expect(currentApprovedRuleIds(['web'],[{id:'web',protocol:'https'}],rules)).toEqual(rules.map(row=>row.id));
});
