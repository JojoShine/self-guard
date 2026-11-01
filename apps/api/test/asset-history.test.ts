import {test} from 'node:test';import assert from 'node:assert/strict';import {assetDiff} from '../src/asset-history';
test('asset history ignores heartbeat diagnostics and array reordering but captures meaningful changes',()=>{
 const before={hostname:'x',inventory:{packages:[{name:'b',version:'1'},{name:'a',version:'1'}],agentDiagnostics:{queue:0}}};
 assert.deepEqual(assetDiff(before,{...before,inventory:{packages:[{name:'a',version:'1'},{name:'b',version:'1'}],agentDiagnostics:{queue:10}}}),{});
 const diff=assetDiff(before,{...before,owner:'analyst',inventory:{packages:[{name:'a',version:'2'},{name:'b',version:'1'}]}});assert.ok(diff.inventory);assert.deepEqual(diff.owner,{before:null,after:'analyst'});assert.ok(!JSON.stringify(diff).includes('agentDiagnostics'));
});
test('actual application version changes are recorded without treating reordered inputs as drift',()=>{const before={inventory:{components:[{ecosystem:'Go',name:'stdlib',version:'1.24.0',path:'/srv/app'}]}};assert.ok(assetDiff(before,{inventory:{components:[{ecosystem:'Go',name:'stdlib',version:'1.24.1',path:'/srv/app'}]}}).inventory);assert.deepEqual(assetDiff(before,{...before,inventory:{...before.inventory,componentCollection:{complete:false}}}),{})});
