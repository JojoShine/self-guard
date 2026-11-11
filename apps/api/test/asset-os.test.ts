import {test} from 'node:test';import assert from 'node:assert/strict';import {assetOperatingSystemData} from '../src/asset-os';import {assetInput} from '../src/validation';
import {isLinuxAsset} from '../src/asset-os';
test('Linux operations accept actual distribution names without rewriting the registered OS',()=>{
 for(const os of ['linux','Linux','Ubuntu 22.04','CentOS Linux 7','银河麒麟高级服务器 V10','Kylin V10','统信 UOS V20','openEuler 22.03']){const asset={os};assert.equal(isLinuxAsset(asset),true,os);assert.equal(asset.os,os);}
 for(const os of ['Windows 11','Windows Subsystem for Linux','macOS 14','darwin','FreeBSD','other',''])assert.equal(isLinuxAsset({os}),false,os);
});
test('observed Agent platform takes precedence over declared display names for Linux operations',()=>{
 assert.equal(isLinuxAsset({os:'Custom enterprise OS',inventory:{os:'linux'}}),true);
 for(const os of ['windows','darwin','freebsd'])assert.equal(isLinuxAsset({os:'Ubuntu 22.04',inventory:{os}}),false);
 assert.equal(isLinuxAsset({os:'Ubuntu 22.04',inventory:null}),true);
});
test('OS registration keeps Linux family and independent distribution metadata',()=>{const value=assetInput.parse({hostname:'owned',os:'linux',osDistribution:'ubuntu',osVersion:'24.04'});assert.equal(assetOperatingSystemData(value).osDistribution,'ubuntu');assert.throws(()=>assetOperatingSystemData({...value,os:'windows'}));});
test('changing family clears stale registration while legacy clients remain compatible',()=>{assert.deepEqual(assetOperatingSystemData({os:'windows'},{os:'linux',osDistribution:'ubuntu',osVersion:'24.04'}),{os:'windows',osDistribution:null,osVersion:null});assert.deepEqual(assetOperatingSystemData({owner:'operator'},{os:'linux',osDistribution:'ubuntu',osVersion:'24.04'}),{owner:'operator'});assert.equal(assetInput.parse({hostname:'legacy',os:'Linux custom'}).os,'Linux custom');});
test('changing distribution clears old version and OS history records registration independently',async()=>{assert.deepEqual(assetOperatingSystemData({osDistribution:'centos'},{os:'linux',osDistribution:'ubuntu',osVersion:'24.04'}),{osDistribution:'centos',osVersion:null});const {assetDiff}=await import('../src/asset-history');assert.deepEqual(assetDiff({os:'linux',osDistribution:'uos',osVersion:'20'},{os:'linux',osDistribution:'ubuntu',osVersion:'24.04'}),{osDistribution:{before:'uos',after:'ubuntu'},osVersion:{before:'20',after:'24.04'}});});
