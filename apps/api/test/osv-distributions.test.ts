import {test} from 'node:test';import assert from 'node:assert/strict';
import {normalizeIntelligence} from '../src/intelligence-normalize';import {assessInventory,inventoryComponents} from '../src/intelligence-match';
const source={feedId:'vendor',snapshotId:'frozen',provider:'OSV',version:'official',sourceSha256:'a'.repeat(64),stale:false};
const affected=(ecosystem:string)=>({package:{ecosystem,name:'php8.3',purl:'pkg:deb/ubuntu/php8.3?arch=source&distro=noble'},ranges:[{type:'ECOSYSTEM',events:[{introduced:'0'},{fixed:'8.3.6-0ubuntu0.24.04.5'}]}]});

test('Ubuntu standard LTS matches actual source version while Pro remains a separate scope',()=>{
 const raw={id:'UBUNTU-CVE-2025-6491',modified:'2026-10-31T00:00:00Z',upstream:['CVE-2025-6491'],related:['USN-7648-1'],severity:[{type:'Ubuntu',score:'medium'}],affected:[affected('Ubuntu:24.04:LTS'),affected('Ubuntu:Pro:24.04:LTS')]};
 const record=normalizeIntelligence('OSV',raw).records[0];assert.equal(record.affected[0].ecosystem,'Ubuntu:24.04');assert.equal(record.affected[0].reportedEcosystem,'Ubuntu:24.04:LTS');assert.equal(record.affected[1].ecosystem,'Ubuntu:Pro:24.04:LTS');assert.ok(record.aliases.includes('CVE-2025-6491'));assert.equal(record.severity,'MEDIUM');assert.deepEqual(record.metadata.upstream,['CVE-2025-6491']);
 const inventory={distribution:{id:'ubuntu',versionId:'24.04'},distributionCollection:{complete:true},packages:[{name:'php8.3-cli',version:'8.3.6-0ubuntu0.24.04.4',origin:'php8.3',sourceVersion:'8.3.6-0ubuntu0.24.04.4',manager:'dpkg'}],packageCollection:{complete:true}};
 const result=assessInventory(inventory,[{source,record}]);assert.equal(result.findings.length,1);assert.equal(result.findings[0].identity,'CVE-2025-6491');assert.equal(result.findings[0].status,'CONFIRMED');assert.equal(result.findings[0].evidence.applicability.length,1);
 const proOnly=normalizeIntelligence('OSV',{...raw,affected:[affected('Ubuntu:Pro:24.04:LTS')]}).records[0];const missing=assessInventory(inventory,[{source,record:proOnly}]);assert.equal(missing.findings.length,0);assert.equal(missing.coverage.status,'INCONCLUSIVE');
});

test('a downstream advisory retains multiple upstream CVEs without calling them aliases of one vulnerability',()=>{
 const record=normalizeIntelligence('OSV',{id:'RLSA-2026:92428',modified:'2026-10-31T00:00:00Z',upstream:['CVE-2026-111497','CVE-2026-114148'],affected:[{package:{ecosystem:'Rocky Linux:9',name:'kernel'},ranges:[{type:'ECOSYSTEM',events:[{introduced:'0'},{fixed:'0:5.14.0-999.el9'}]}]}]}).records[0];
 assert.deepEqual(record.metadata.upstream,['CVE-2026-111497','CVE-2026-114148']);assert.deepEqual(record.aliases,['RLSA-2026:92428']);
 const inventory={distribution:{id:'rocky',versionId:'9.7'},distributionCollection:{complete:true},packages:[{name:'kernel',version:'0:5.14.0-500.el9',manager:'rpm'}],packageCollection:{complete:true}};
 assert.equal(inventoryComponents(inventory).components[0].ecosystem,'Rocky Linux:9');assert.equal(assessInventory(inventory,[{source,record}]).findings.length,1);
});

test('only the managed Ubuntu archive profile accepts the larger official record budget',()=>{
 const raw={id:'UBUNTU-CVE-2026-12345',modified:'2026-10-31T00:00:00Z',affected:[affected('Ubuntu:24.04:LTS')],originalExtra: 'x'.repeat(3*1024*1024)};
 assert.throws(()=>normalizeIntelligence('OSV',raw));assert.equal(normalizeIntelligence('OSV',raw,'UBUNTU_ARCHIVE').records.length,1);
});

test('Ubuntu whole-archive source requires an explicit standard release and rejects unrelated scope fields',async()=>{
 const {feedUrl}=await import('../src/intelligence');
 assert.equal(feedUrl('OSV',{mode:'ECOSYSTEM',ecosystem:'Ubuntu',release:'24.04'}).href,'https://storage.googleapis.com/osv-vulnerabilities/Ubuntu/all.zip');
 for(const config of [{mode:'ECOSYSTEM',ecosystem:'Ubuntu'},{mode:'ECOSYSTEM',ecosystem:'Ubuntu',release:'Pro:24.04'},{mode:'ECOSYSTEM',ecosystem:'Go',release:'24.04'}])assert.throws(()=>feedUrl('OSV',config));
});

test('large Ubuntu update notices preserve all links but never become duplicate CVE findings',()=>{
 const upstream=['CVE-2025-6491',...Array.from({length:1214},(_,index)=>'CVE-2026-'+(10000+index))],notice={id:'USN-7156-1',modified:'2026-10-31T00:00:00Z',upstream,affected:[affected('Ubuntu:24.04:LTS')]};
 const record=normalizeIntelligence('OSV',notice,'UBUNTU_ARCHIVE').records[0];assert.equal(record.purpose,'METADATA');assert.equal(record.metadata.vendorAdvisory,true);assert.deepEqual(record.metadata.upstream,upstream);assert.deepEqual(record.aliases,['USN-7156-1']);
 const cve=normalizeIntelligence('OSV',{id:'UBUNTU-CVE-2025-6491',modified:notice.modified,upstream:['CVE-2025-6491'],affected:notice.affected}).records[0];
 const inventory={distribution:{id:'ubuntu',versionId:'24.04'},distributionCollection:{complete:true},packages:[{name:'php8.3',version:'8.3.6-0ubuntu0.24.04.4',origin:'php8.3',sourceVersion:'8.3.6-0ubuntu0.24.04.4'}],packageCollection:{complete:true}};
 const result=assessInventory(inventory,[{source,record},{source,record:cve}]);assert.equal(result.findings.length,1);assert.equal(result.findings[0].identity,'CVE-2025-6491');
});
