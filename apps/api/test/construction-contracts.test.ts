import {test} from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,sign} from 'node:crypto';
import {artifactManifestInput,verifyArtifactManifest,verifyPackageManifest,scanScopeInput,resolveScanScope,coverageSummary} from '../src/construction-contracts';

const now=new Date('2026-10-31T00:00:00Z');
const assets=[
 {id:'a',businessId:'payments',tags:['prod'],type:'HOST',archivedAt:null,inventoryAt:new Date(now.getTime()-60000)},
 {id:'b',businessId:'payments',tags:['prod','maintenance'],type:'HOST',archivedAt:null,inventoryAt:now},
 {id:'c',businessId:'other',tags:['prod'],type:'HOST',archivedAt:null,inventoryAt:now},
 {id:'d',businessId:'payments',tags:['prod'],type:'HOST',archivedAt:now,inventoryAt:now},
 {id:'e',businessId:'payments',tags:['prod'],type:'HOST',archivedAt:null,inventoryAt:new Date(now.getTime()-25*3600000)},
];
test('scope rejects implicit all and empty include groups',()=>{
 assert.equal(scanScopeInput.safeParse({}).success,false);
 assert.equal(scanScopeInput.safeParse({include:[{}]}).success,false);
 assert.equal(scanScopeInput.safeParse({include:[{assetIds:[]}]}).success,false);
 assert.equal(scanScopeInput.safeParse({allAuthorized:true,include:[{assetIds:['a']}]}).success,false);
});
test('installation packages require an independent signed envelope bound to the executable release',()=>{
 const keys=generateKeyPairSync('ed25519'),root=keys.publicKey.export({format:'der',type:'spki'}).subarray(-32).toString('base64');
 const release={version:'1.0.0',sha256:'a'.repeat(64),architecture:'arm64'};
 const manifest={kind:'selfguard-agent-package-v1',version:release.version,executableSha256:release.sha256,architecture:'arm64',os:'linux',format:'deb',sha256:'b'.repeat(64),size:256,expiresAt:'2026-11-30T00:00:00Z'};
 const envelope=(m:any)=>{const raw=Buffer.from(JSON.stringify(m));return {manifestBytes:raw.toString('base64'),signature:sign(null,raw,keys.privateKey).toString('base64')};};
 assert.deepEqual(verifyPackageManifest(envelope(manifest),root,release,now),manifest);
 for(const change of [{kind:'other-purpose'},{version:'2.0.0'},{architecture:'amd64'},{executableSha256:'c'.repeat(64)},{format:'shell'},{expiresAt:'2026-10-01T00:00:00Z'}])assert.throws(()=>verifyPackageManifest(envelope({...manifest,...change}),root,release,now));
 assert.throws(()=>verifyArtifactManifest(envelope(manifest),root,now));
});
test('scope intersects authorization, ANDs dimensions, unions groups, excludes before selection and explains coverage',()=>{
 const scope=scanScopeInput.parse({include:[{businessIds:['payments'],tags:['prod'],types:['HOST']}],exclude:[{tags:['maintenance']} ]});
 const result=resolveScanScope(scope,assets,new Set(['a','b','d','e']),now);
 assert.deepEqual(result.selected.map(x=>x.id),['a']);
 assert.deepEqual(result.skipped.map(x=>[x.id,x.reason]),[['b','EXCLUDED'],['d','ARCHIVED'],['e','STALE_INVENTORY']]);
 assert.ok(!JSON.stringify(result).includes('other'));
});
test('expired exclusions resume checks and explicit all never grants additional authorization',()=>{
 const scope=scanScopeInput.parse({allAuthorized:true,exclude:[{assetIds:['a'],expiresAt:'2026-10-30T00:00:00Z'}]});
 assert.deepEqual(resolveScanScope(scope,assets,new Set(['a']),now).selected.map(x=>x.id),['a']);
 assert.equal(resolveScanScope(scope,assets,new Set(),now).selected.length,0);
});
test('inventory-required checks distinguish unavailable or future inventory, active targets need not have inventory',()=>{
 const scope=scanScopeInput.parse({allAuthorized:true});
 const extra=[{...assets[0],id:'missing',inventoryAt:null},{...assets[0],id:'future',inventoryAt:new Date(now.getTime()+60000)}];
 assert.deepEqual(resolveScanScope(scope,extra,new Set(['missing','future']),now).skipped.map(x=>x.reason),['MISSING_INVENTORY','INVALID_INVENTORY_TIME']);
 assert.equal(resolveScanScope(scope,extra,new Set(['missing','future']),now,false).selected.length,2);
});
test('coverage does not count skipped or inconclusive targets as clean checks',()=>{
 assert.deepEqual(coverageSummary(['CONFIRMED','NOT_FOUND','SKIPPED','INCONCLUSIVE','POTENTIAL','NOT_APPLICABLE']),{total:6,executed:3,confirmed:1,potential:1,notFound:1,notApplicable:1,skipped:1,inconclusive:1});
});
test('artifact manifest verifies exact bytes, expiry, platform, digest and trusted key',()=>{
 const keys=generateKeyPairSync('ed25519');
 const m={version:'1.0.0',sequence:1,sha256:'a'.repeat(64),size:120,os:'linux',architecture:'arm64',expiresAt:'2026-11-30T00:00:00Z'};
 const raw=Buffer.from(JSON.stringify(m));const envelope={manifestBytes:raw.toString('base64'),signature:sign(null,raw,keys.privateKey).toString('base64')};
 const root=keys.publicKey.export({format:'der',type:'spki'}).subarray(-32).toString('base64');
 assert.deepEqual(verifyArtifactManifest(envelope,root,now),m);
 assert.throws(()=>verifyArtifactManifest({...envelope,manifestBytes:Buffer.from(JSON.stringify({...m,size:121})).toString('base64')},root,now));
 assert.throws(()=>verifyArtifactManifest(envelope,root,new Date('2026-12-01')));
 assert.throws(()=>verifyArtifactManifest(envelope,'',now));
 assert.equal(artifactManifestInput.safeParse({...m,sequence:0}).success,false);
 assert.equal(artifactManifestInput.safeParse({...m,os:'darwin'}).success,false);
});
