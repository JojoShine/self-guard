import {it,expect,vi} from 'vitest';vi.mock('./api',()=>({api:vi.fn()}));import {activePlanChoices} from './ActiveScanPanel';
it('derives only selected approved endpoint assets and keeps asset and tag exclusions as separate groups',()=>{
 const value=activePlanChoices({endpointIds:['one'],templateIds:['template'],excludeAssets:['b'],excludeTags:['maintenance']},[{id:'one',assetId:'a'},{id:'two',assetId:'other'}]);expect(value.scope.include).toEqual([{assetIds:['a'],types:['SERVICE']}]);expect(value.scope.exclude).toEqual([{assetIds:['b']},{tags:['maintenance']}]);expect(()=>activePlanChoices({endpointIds:['missing'],templateIds:['template']},[])).toThrow('重新选择');
});
