import {test} from 'node:test';import assert from 'node:assert/strict';
import {assessPinnedInventory} from '../src/scan-intelligence';
import {stageOsvEcosystemSnapshot} from '../src/intelligence-osv-stage';
import {withRawArchive,currentRawArchive} from '../src/intelligence-artifacts';

test('frozen ecosystem snapshots propagate unscoped source gaps and query wildcard identities',async()=>{
 const pin:any={feedId:'feed',snapshotId:'snapshot',provider:'OSV',version:'fixed',sourceSha256:'a'.repeat(64),configHash:'config',lastSuccessAt:new Date().toISOString(),staleAfterHours:24,stale:false,scope:{mode:'ECOSYSTEM',ecosystem:'npm'}};
 for(const activeUnscopedAffected of [0,1,undefined,-1,'0']){
  const keys:string[]=[];const db:any={vulnerabilityFeed:{findUnique:async()=>({enabled:true,configHash:'config'})},vulnerabilitySnapshot:{findFirst:async()=>({normalizerVersion:'selfguard-intelligence-v4',config:pin.scope,sourceManifest:{normalization:{activeUnscopedAffected}}})},vulnerabilityRecord:{findMany:async(query:any)=>{keys.push(...(query.where.packages?.hasSome||[]));return []}}};
  const result=await assessPinnedInventory(db,{components:[{ecosystem:'npm',name:'example',version:'1.0.0'}],componentCollection:{complete:true}},[pin]);
  assert.ok(keys.includes('npm:*'));assert.equal(result.coverage.status,activeUnscopedAffected===0?'COMPLETED':'INCONCLUSIVE');
 }
});

test('full archive staging keeps unscoped records and records only active gaps after complete validation',async()=>{
 const rows:any[]=[],documents=[{id:'OSV-UNSCOPED',modified:'2026-10-31T00:00:00Z',affected:[{ranges:[{type:'GIT',repo:'https://github.com/example/code',events:[{introduced:'0'}]}]}]},{id:'OSV-WITHDRAWN',modified:'2026-10-31T00:00:00Z',withdrawn:'2026-10-31T00:00:00Z',affected:[{ranges:[]}]}];let completed=false,aborted=false;
 const db:any={$transaction:async(work:any)=>work({vulnerabilityFeed:{updateMany:async()=>({count:1})},vulnerabilityRecord:{createMany:async(input:any)=>rows.push(...input.data)},vulnerabilitySnapshot:{update:async()=>{}}})};
 await withRawArchive(1024,async()=>{const result=await stageOsvEcosystemSnapshot(db,{id:'feed',configHash:'config',config:{ecosystem:'npm'}},'snapshot','lease',{sourceSha256:'a'.repeat(64),document:{kind:'OSV_ECOSYSTEM_ARCHIVE',ecosystem:'npm',version:'fixture',entries:(async function*(){for(const row of documents)yield row;completed=true})(),validate(){assert.ok(completed)},abort(){aborted=true}}});assert.equal(result.recordCount,2);assert.deepEqual(currentRawArchive()?.manifest.normalization,{activeUnscopedAffected:1,coveredEcosystems:[]});assert.match(result.coverage,/1 项未提供软件身份/);});
 assert.ok(aborted);assert.equal(rows.length,2);assert.equal(rows[0].purpose,'CANDIDATE');assert.equal(rows[0].affected[0].package,undefined);
});

test('vendor archive coverage follows validated release namespaces and never accepts a missing v5 gap counter',async()=>{
 const pin:any={feedId:'vendor',snapshotId:'frozen',provider:'OSV',version:'v5',sourceSha256:'a'.repeat(64),configHash:'config',lastSuccessAt:new Date().toISOString(),staleAfterHours:24,scope:{mode:'ECOSYSTEM',ecosystem:'Rocky Linux'}};
 const inventory={distribution:{id:'rocky',versionId:'9.7'},distributionCollection:{complete:true},packages:[{name:'kernel',version:'0:5.14.0-500.el9',manager:'rpm'}],packageCollection:{complete:true}};
 for(const count of [0,1,undefined]){
  const db:any={vulnerabilityFeed:{findUnique:async()=>({enabled:true,configHash:'config'})},vulnerabilitySnapshot:{findFirst:async()=>({normalizerVersion:'selfguard-intelligence-v5',config:pin.scope,sourceManifest:{normalization:{activeUnscopedAffected:count,coveredEcosystems:['Rocky Linux:9']}}})},vulnerabilityRecord:{findMany:async()=>[]}};
  const result=await assessPinnedInventory(db,inventory,[pin]);assert.equal(result.coverage.status,count===0?'COMPLETED':'INCONCLUSIVE');
 }
 const npm={...pin,scope:{mode:'ECOSYSTEM',ecosystem:'npm'}};
 const db:any={vulnerabilityFeed:{findUnique:async()=>({enabled:true,configHash:'config'})},vulnerabilitySnapshot:{findFirst:async()=>({normalizerVersion:'selfguard-intelligence-v5',config:npm.scope,sourceManifest:{}})},vulnerabilityRecord:{findMany:async()=>[]}};
 assert.equal((await assessPinnedInventory(db,{components:[{ecosystem:'npm',name:'example',version:'1.0.0'}],componentCollection:{complete:true}},[npm])).coverage.status,'INCONCLUSIVE');
});

test('Ubuntu staging binds one standard release and retains the original source identity while filtering other scopes',async()=>{
 const rows:any[]=[],affected=(ecosystem:string)=>({package:{ecosystem,name:'example'},ranges:[{type:'ECOSYSTEM',events:[{introduced:'0'},{fixed:'2.0-1'}]}]}),documents=[{id:'UBUNTU-CVE-2026-12345',modified:'2026-10-31T00:00:00Z',affected:[affected('Ubuntu:24.04:LTS'),affected('Ubuntu:Pro:24.04:LTS'),affected('Ubuntu:22.04:LTS')]},{id:'UBUNTU-CVE-2026-12346',modified:'2026-10-31T00:00:00Z',affected:[affected('Ubuntu:22.04:LTS')]}];let selected='';
 const db:any={$transaction:async(work:any)=>work({vulnerabilityFeed:{updateMany:async()=>({count:1})},vulnerabilityRecord:{createMany:async(input:any)=>rows.push(...input.data)},vulnerabilitySnapshot:{update:async()=>{}}})};
 await withRawArchive(1024,async()=>{const result=await stageOsvEcosystemSnapshot(db,{id:'feed',configHash:'config',config:{ecosystem:'Ubuntu',release:'24.04'}},'snapshot','lease',{sourceSha256:'a'.repeat(64),document:{kind:'OSV_ECOSYSTEM_ARCHIVE',ecosystem:'Ubuntu',version:'fixture',bindUbuntuRelease(value:string){selected=value},entries:(async function*(){yield* documents})(),validate(){},abort(){}}});assert.equal(result.recordCount,1);assert.equal(selected,'24.04');assert.deepEqual(currentRawArchive()?.manifest.normalization,{activeUnscopedAffected:0,coveredEcosystems:['Ubuntu:24.04']});});
 assert.equal(rows[0].affected.length,1);assert.deepEqual(rows[0].packages,['Ubuntu:24.04:example']);assert.equal(rows[0].affected[0].reportedEcosystem,'Ubuntu:24.04:LTS');assert.equal(rows[0].metadata.archiveScope.excludedAffected,2);
});
