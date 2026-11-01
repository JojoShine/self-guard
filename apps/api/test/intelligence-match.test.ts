import {test} from 'node:test';import assert from 'node:assert/strict';import {assessInventory} from '../src/intelligence-match';
const source={feedId:'feed',snapshotId:'snapshot',provider:'OSV',version:'2026',sourceSha256:'a'.repeat(64),stale:false};
function entry(overrides:any={}){return {source,record:{externalId:'GHSA-fixture',aliases:['GHSA-fixture','CVE-2026-12345'],summary:'实际软件漏洞',details:'软件版本在受影响区间',purpose:'PACKAGE',severity:null,withdrawnAt:null,scores:[],references:[],metadata:{},affected:[{kind:'OSV_PACKAGE',ecosystem:'npm',package:'example',scheme:'SEMVER',versions:[],ranges:[{type:'SEMVER',events:[{introduced:'0'},{fixed:'1.2.3'}]}]}],...overrides}}}
const inventory={components:[{ecosystem:'npm',name:'example',version:'1.2.2',path:'/srv/app/package-lock.json'}],componentCollection:{complete:true}};
test('Python registry-equivalent names match actual inventory and preserve the reported spelling',()=>{
 const record=entry({affected:[{kind:'OSV_PACKAGE',ecosystem:'PyPI',package:'friendly-bard',scheme:'PEP440',versions:['1.0'],ranges:[]}]});
 const result=assessInventory({components:[{ecosystem:'PyPI',name:'FrIeNdLy_._Bard',version:'1.0'}],componentCollection:{complete:true}},[record]);assert.equal(result.findings.length,1);assert.equal(result.findings[0].evidence.component.reportedName,'FrIeNdLy_._Bard');
 const invalid=assessInventory({components:[{ecosystem:'PyPI',name:'friendly-bard\n',version:'1.0'}],componentCollection:{complete:true}},[record]);assert.equal(invalid.coverage.status,'INCONCLUSIVE');assert.equal(invalid.findings.length,0);
});
test('confirmed package/version evidence is enriched through shared CVE aliases without treating KEV or NVD as independent detections',()=>{
 const kev=entry({externalId:'CVE-2026-12345',aliases:['CVE-2026-12345'],purpose:'PRIORITY',affected:[],metadata:{knownExploited:true,requiredAction:'升级软件'}}),nvd=entry({externalId:'CVE-2026-12345',aliases:['CVE-2026-12345'],purpose:'CANDIDATE',affected:[{kind:'CPE_CONFIGURATION',configuration:[]}],severity:'HIGH',scores:[{version:'3.1',score:9.8,source:'NVD'}]});
 kev.source={...source,feedId:'kev-feed',provider:'CISA_KEV'};nvd.source={...source,feedId:'nvd-feed',provider:'NVD'};
 const result=assessInventory(inventory,[entry(),kev,nvd]);assert.equal(result.findings.length,1);const hit=result.findings[0];assert.equal(hit.status,'CONFIRMED');assert.equal(hit.evidence.component.version,'1.2.2');assert.equal(hit.severity,'HIGH');assert.equal(hit.evidence.knownExploited,true);assert.equal(hit.evidence.sources.length,3);assert.equal(hit.evidence.applicability.length,1);
 assert.equal(assessInventory(inventory,[kev,nvd]).findings.length,0);assert.equal(assessInventory(inventory,[kev,nvd]).coverage.status,'INCONCLUSIVE');
});
test('fixed boundaries, withdrawn advisories and ecosystem identity do not create false risk findings',()=>{
 assert.equal(assessInventory({...inventory,components:[{...inventory.components[0],version:'1.2.3'}]},[entry()]).findings.length,0);
 assert.equal(assessInventory(inventory,[entry({withdrawnAt:'2026-10-01T00:00:00Z'})]).findings.length,0);
 assert.equal(assessInventory({...inventory,components:[{...inventory.components[0],ecosystem:'PyPI'}]},[entry()]).findings.length,0);
});
test('sparse vendor findings show an attributed exact-CVE description while retaining vendor applicability',()=>{
 const vendor=entry({details:''}),nvd=entry({externalId:'CVE-2026-12345',aliases:['CVE-2026-12345'],details:'Exact CVE vulnerability explanation',purpose:'CANDIDATE',affected:[]}),kev=entry({externalId:'CVE-2026-12345',aliases:['CVE-2026-12345'],details:'Known exploitation context',purpose:'PRIORITY',affected:[]});
 nvd.source={...source,feedId:'nvd',provider:'NVD'};kev.source={...source,feedId:'kev',provider:'CISA_KEV'};
 const hit=assessInventory(inventory,[vendor,kev,nvd]).findings[0];assert.equal(hit.evidence.description,'Exact CVE vulnerability explanation');assert.equal(hit.evidence.descriptionSource.provider,'NVD');assert.equal(hit.evidence.descriptionSource.externalId,'CVE-2026-12345');assert.equal(hit.evidence.descriptionSource.snapshotId,source.snapshotId);assert.equal(hit.evidence.applicability.length,1);
 assert.equal(assessInventory(inventory,[entry(),nvd]).findings[0].evidence.description,'软件版本在受影响区间');
 assert.equal(assessInventory(inventory,[vendor,{...nvd,record:{...nvd.record,withdrawnAt:'2026-10-01T00:00:00Z'}},kev]).findings[0].evidence.description,'Known exploitation context');
 const unrelated={...nvd,record:{...nvd.record,externalId:'CVE-2026-99999',aliases:['CVE-2026-99999']}};assert.equal(assessInventory(inventory,[vendor,unrelated]).findings[0].evidence.description,'');
 assert.equal(assessInventory(inventory,[nvd,kev]).findings.length,0,'Descriptions and priority must not become package detections');
});
test('Alpine uses matching release/source origin and earliest fix, not OR of every later fixed version',()=>{
 const record=entry({affected:[{kind:'DISTRIBUTION_FIX',ecosystem:'Alpine:v3.24',distribution:'alpine',release:'3.24',repository:'main',package:'openssl',scheme:'APK',fixed:'3.5.1-r0'},{kind:'DISTRIBUTION_FIX',ecosystem:'Alpine:v3.24',distribution:'alpine',release:'3.24',repository:'main',package:'openssl',scheme:'APK',fixed:'3.5.2-r0'}]});
 const host={distribution:{id:'alpine',versionId:'3.24.0'},distributionCollection:{complete:true},packageCollection:{complete:true},packages:[{name:'libcrypto3',origin:'openssl',version:'3.5.1-r0'}]};
 assert.equal(assessInventory(host,[record]).findings.length,0);assert.equal(assessInventory({...host,packages:[{...host.packages[0],version:'3.5.0-r0'}]},[record]).findings.length,1);assert.equal(assessInventory({...host,distribution:{id:'alpine',versionId:'3.23.0'}},[record]).findings.length,0);
});
test('unsupported applicable ranges, stale sources and incomplete inventory remain visible rather than becoming a clean result',()=>{
 const unknown=entry({affected:[{kind:'OSV_PACKAGE',ecosystem:'npm',package:'example',scheme:'UNKNOWN',versions:[],ranges:[{type:'GIT',events:[{introduced:'abc'},{fixed:'def'}]}]}]});assert.equal(assessInventory(inventory,[unknown]).coverage.status,'INCONCLUSIVE');
 const stale=entry();stale.source={...source,stale:true};assert.equal(assessInventory(inventory,[stale]).findings[0].status,'POTENTIAL');assert.equal(assessInventory({...inventory,componentCollection:{complete:false}},[entry()]).coverage.status,'INCONCLUSIVE');
 const unrated=assessInventory(inventory,[entry()]).findings[0];assert.equal(unrated.severity,null);
});
test('distribution checks use Debian source versions and refuse RPM inventory that discarded epoch',()=>{
 const deb=entry({affected:[{kind:'OSV_PACKAGE',ecosystem:'Debian:12',package:'openssl',scheme:'DEBIAN',versions:[],ranges:[{type:'ECOSYSTEM',events:[{introduced:'0'},{fixed:'3.0.10-1'}]}]}]});
 const inventory={distribution:{id:'debian',versionId:'12'},distributionCollection:{complete:true},packageCollection:{complete:true},packages:[{name:'libssl3',version:'3.0.9-1+b9',origin:'openssl',sourceVersion:'3.0.9-1',manager:'dpkg'}]};
 const hit=assessInventory(inventory,[deb]).findings[0];assert.equal(hit.evidence.applicability[0].actual,'3.0.9-1');assert.equal(hit.evidence.component.version,'3.0.9-1+b9');
 const rpm=entry({affected:[{kind:'OSV_PACKAGE',ecosystem:'Rocky Linux:9',package:'example',scheme:'RPM',versions:[],ranges:[{type:'ECOSYSTEM',events:[{introduced:'0'},{fixed:'1:1.0-1'}]}]}]});
 const old={distribution:{id:'rocky',versionId:'9'},distributionCollection:{complete:true},packageCollection:{complete:true},packages:[{name:'example',version:'2.0-1'}]};assert.equal(assessInventory(old,[rpm]).findings.length,0);assert.equal(assessInventory(old,[rpm]).coverage.status,'INCONCLUSIVE');
 assert.equal(assessInventory({...old,packages:[{name:'example',version:'0:2.0-1',epoch:'0',manager:'rpm'}]},[rpm]).findings.length,1);
});
test('uncovered components are not counted as checked, while an explicitly complete ecosystem can prove no matching advisory',()=>{
 const mixed={components:[...inventory.components,{ecosystem:'PyPI',name:'uncovered-python',version:'1.0'}],componentCollection:{complete:true}};const partial=assessInventory(mixed,[entry()]);assert.equal(partial.coverage.status,'INCONCLUSIVE');assert.equal(partial.coverage.checked,1);assert.equal(partial.coverage.unknown,1);
 const clean=assessInventory(inventory,[],['npm']);assert.equal(clean.coverage.status,'COMPLETED');assert.equal(clean.coverage.checked,1);assert.equal(clean.findings.length,0);assert.equal(assessInventory(mixed,[],['npm']).coverage.status,'INCONCLUSIVE');
});
test('lock and SBOM versions retain candidate provenance instead of creating confirmed installed vulnerabilities',()=>{
 for(const provenance of ['LOCK_FILE','SBOM']){const result=assessInventory({...inventory,components:[{...inventory.components[0],provenance,sourceSha256:'c'.repeat(64),bomRef:'component-1',dependsOn:['component-2']}]},[entry()]);assert.equal(result.findings[0].status,'POTENTIAL');assert.equal(result.coverage.status,'INCONCLUSIVE');assert.equal(result.findings[0].evidence.component.provenance,provenance);assert.equal(result.findings[0].evidence.component.sourceSha256,'c'.repeat(64));}
});

test('unscoped active source conditions cannot prove an ecosystem clean',()=>{
 const result=assessInventory({components:[{ecosystem:'npm',name:'no-known-record',version:'1.0.0'}],componentCollection:{complete:true}},[],['npm'],['npm']);
 assert.equal(result.coverage.status,'INCONCLUSIVE');assert.equal(result.coverage.checked,0);assert.equal(result.coverage.unknown,1);assert.equal(result.findings.length,0);
});

test('ecosystem wildcard ranges are considered and missing version conditions never prove clean',()=>{
 const wildcard=entry({affected:[{kind:'OSV_PACKAGE',ecosystem:'npm',package:'*',scheme:'SEMVER',ranges:[{type:'SEMVER',events:[{introduced:'0'},{fixed:'2.0.0'}]}],versions:[]}]});assert.equal(assessInventory(inventory,[wildcard]).findings.length,1);
 const missing=entry({affected:[{kind:'OSV_PACKAGE',ecosystem:'npm',package:'example',scheme:'SEMVER',ranges:[],versions:[]}]});const result=assessInventory(inventory,[missing],['npm']);assert.equal(result.coverage.status,'INCONCLUSIVE');assert.equal(result.coverage.checked,0);
});
