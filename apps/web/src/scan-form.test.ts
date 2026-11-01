import {it,expect} from 'vitest';import {scanScopeFromForm} from './scan-form';
it('requires explicit targets or explicit full authorization, preserving exclusions and UTC expiry',()=>{
 expect(()=>scanScopeFromForm({scopeMode:'assets',targets:[]})).toThrow('明确目标');expect(scanScopeFromForm({scopeMode:'businesses',targets:['stable-business-id'],excludeTags:['maintenance'],excludeUntil:'2026-11-01'})).toEqual({allAuthorized:false,include:[{businessIds:['stable-business-id']}],exclude:[{tags:['maintenance'],expiresAt:'2026-11-01T23:59:59.999Z'}],inventoryMaxAgeHours:24});expect(scanScopeFromForm({scopeMode:'all',targets:['old-selection']})).toMatchObject({allAuthorized:true,include:[]});
});
