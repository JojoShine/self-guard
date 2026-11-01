import {test} from 'node:test';import assert from 'node:assert/strict';
import {executionScopeInput,executionIdentityInput,executionScopeAllows,intersectExecutionScope} from '../src/scan-execution-contracts';
const asset='10000000-0000-4000-8000-000000000001',business='10000000-0000-4000-8000-000000000002';
test('a service identity has no implicit full scope, credentials or arbitrary capabilities',()=>{
 for(const input of [{},{assetIds:[],businessIds:[]},{allAuthorized:true,assetIds:[asset]},{assetIds:[asset,asset]},{assetIds:['not-an-asset']},{assetIds:[asset],role:'ADMIN'}])assert.equal(executionScopeInput.safeParse(input).success,false);
 assert.ok(executionScopeInput.safeParse({allAuthorized:true}).success);assert.ok(executionIdentityInput.safeParse({name:'生产检查',scope:{assetIds:[asset]}}).success);
 for(const input of [{password:'secret'},{token:'token'},{role:'ADMIN'},{approvedBy:business},{version:2}])assert.equal(executionIdentityInput.safeParse({name:'生产检查',scope:{assetIds:[asset]},...input}).success,false);
});
test('identity assets and businesses form only their own explicit union',()=>{
 const scope=executionScopeInput.parse({assetIds:[asset],businessIds:[business]});assert.equal(executionScopeAllows(scope,{id:asset}),true);assert.equal(executionScopeAllows(scope,{id:'other'},business),true);assert.equal(executionScopeAllows(scope,{id:'other'},'other-business'),false);
 const full=executionScopeInput.parse({allAuthorized:true});assert.equal(executionScopeAllows(full,{id:'other'}),true);
});
test('identity scope restricts existing plan selection and cannot add an identity-only asset',()=>{
 const resolved={selected:[{id:asset,businessId:null},{id:'outside',businessId:null}],skipped:[{id:'excluded',reason:'EXCLUDED'}],checkedAt:'2026-11-01T00:00:00Z'};
 const identity:any={scope:executionScopeInput.parse({assetIds:[asset,'10000000-0000-4000-8000-000000000003']})},result=intersectExecutionScope(resolved,identity);
 assert.deepEqual(result.selected,[resolved.selected[0]]);assert.deepEqual(result.skipped,[{id:'excluded',reason:'EXCLUDED'},{id:'outside',reason:'EXECUTION_IDENTITY_SCOPE'}]);assert.equal(resolved.selected.length,2);assert.equal(intersectExecutionScope(resolved,null),resolved);
});
