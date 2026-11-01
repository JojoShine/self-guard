import {describe,it,expect} from 'vitest';
import {executionFormValue,executionBindingFromForm} from './ScanExecutionFields';
describe('explicit scan grant selection',()=>{
 const identity={id:'owned-identity',name:'Production',enabled:true,version:2},catalog={canManageIdentities:true,executionIdentities:[identity]};
 it('keeps old API and non-admin forms from submitting service grants',()=>{
  expect(executionBindingFromForm({},{})).toEqual({});expect(executionBindingFromForm({executionIdentityChoice:'OWNER'},{...catalog,canManageIdentities:false})).toEqual({});
  expect(()=>executionBindingFromForm({executionIdentityChoice:'owned-identity@2'},{})).toThrow('不会自动改用负责人权限');expect(()=>executionBindingFromForm({executionIdentityChoice:'owned-identity@2'},{...catalog,canManageIdentities:false})).toThrow('不会自动改用负责人权限');
 });
 it('never silently upgrades an already selected grant after catalog refresh',()=>{
  expect(()=>executionBindingFromForm({executionIdentityChoice:'owned-identity@1'},catalog)).toThrow('明确选择当前版本');expect(executionBindingFromForm({executionIdentityChoice:'owned-identity@2'},catalog)).toEqual({executionIdentityId:identity.id,executionIdentityVersion:2});
 });
 it('requires a new explicit selection after disabling the identity and preserves stale plan values for explanation',()=>{
  expect(()=>executionBindingFromForm({executionIdentityChoice:'owned-identity@2'},{...catalog,executionIdentities:[{...identity,enabled:false}]})).toThrow('停用');expect(executionFormValue({executionIdentityId:identity.id,executionIdentityVersion:1})).toBe('owned-identity@1');expect(executionBindingFromForm({executionIdentityChoice:'OWNER'},catalog)).toEqual({executionIdentityId:null});
 });
});
