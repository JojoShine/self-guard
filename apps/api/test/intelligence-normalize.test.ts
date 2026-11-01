import {test} from 'node:test';import assert from 'node:assert/strict';
import {normalizeIntelligence} from '../src/intelligence-normalize';
test('multi-source normalization preserves applicability and never treats prioritization as a detected software vulnerability',()=>{
 const kev=normalizeIntelligence('CISA_KEV',{catalogVersion:'2026.10.30',dateReleased:'2026-10-30T12:00:00Z',count:1,vulnerabilities:[{cveID:'CVE-2021-44228',vendorProject:'Apache',product:'Log4j',vulnerabilityName:'Log4Shell',dateAdded:'2021-12-10',shortDescription:'Remote code execution',requiredAction:'Apply vendor fix',dueDate:'2021-12-24',knownRansomwareCampaignUse:'Known'}]});
 assert.equal(kev.records[0].severity,null);assert.equal(kev.records[0].affected.length,0);assert.equal(kev.records[0].purpose,'PRIORITY');assert.deepEqual(kev.records[0].aliases,['CVE-2021-44228']);
 const alpine=normalizeIntelligence('ALPINE',{distroversion:'v3.24',reponame:'main',packages:[{pkg:{name:'libsample',secfixes:{'1.2.3-r1':['CVE-2021-44228']}}}]});
 assert.equal(alpine.records[0].affected[0].ecosystem,'Alpine:v3.24');assert.equal(alpine.records[0].affected[0].package,'libsample');assert.equal(alpine.records[0].affected[0].fixed,'1.2.3-r1');assert.equal(alpine.records[0].affected[0].scheme,'APK');
 const osv=normalizeIntelligence('OSV',{id:'GHSA-1234-abcd-5678',modified:'2026-10-30T12:00:00Z',aliases:['CVE-2021-44228'],summary:'Real package issue',affected:[{package:{ecosystem:'npm',name:'sample'},ranges:[{type:'SEMVER',events:[{introduced:'0'},{fixed:'2.0.0'}]}]}]});assert.equal(osv.records[0].affected[0].scheme,'SEMVER');assert.equal(osv.records[0].severity,null);assert.ok(osv.records[0].aliases.includes('CVE-2021-44228'));
});
test('NVD retains scoring provenance and complete boolean CPE conditions as candidates',()=>{
 const configs=[{operator:'AND',nodes:[{operator:'OR',cpeMatch:[{vulnerable:true,criteria:'cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*',versionEndExcluding:'2.15.0'}]},{operator:'OR',cpeMatch:[{vulnerable:false,criteria:'cpe:2.3:o:vendor:os:*:*:*:*:*:*:*:*'}]}]}];
 const nvd=normalizeIntelligence('NVD',{totalResults:1,startIndex:0,resultsPerPage:1,timestamp:'2026-10-30T12:00:00Z',vulnerabilities:[{cve:{id:'CVE-2021-44228',published:'2021-12-10T00:00:00.000',lastModified:'2026-10-30T00:00:00.000',vulnStatus:'Analyzed',descriptions:[{lang:'en',value:'Log4Shell'}],configurations:configs,metrics:{cvssMetricV31:[{source:'nvd@nist.gov',type:'Primary',cvssData:{version:'3.1',vectorString:'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',baseScore:10,baseSeverity:'CRITICAL'}}]}}}]});
 assert.deepEqual(nvd.records[0].affected[0].configuration,configs);assert.equal(nvd.records[0].purpose,'CANDIDATE');assert.equal(nvd.records[0].scores[0].source,'nvd@nist.gov');assert.equal(nvd.records[0].severity,'CRITICAL');
});
test('incomplete catalogs and duplicate identities cannot replace a valid snapshot',()=>{
 assert.throws(()=>normalizeIntelligence('CISA_KEV',{catalogVersion:'v1',count:2,vulnerabilities:[]}));assert.throws(()=>normalizeIntelligence('NVD',{startIndex:0,totalResults:2,resultsPerPage:1,vulnerabilities:[]}));assert.throws(()=>normalizeIntelligence('ALPINE',{distroversion:'v3.24',reponame:'main',packages:[{pkg:{name:'sample',secfixes:{'1':['CVE-1']}}},{pkg:{name:'sample',secfixes:{'1':['CVE-1']}}}]}));
});
test('Python package identity normalizes registry-equivalent spellings while retaining the reported source name',()=>{
 const result=normalizeIntelligence('OSV',{id:'PYSEC-2026-1',modified:'2026-10-30T12:00:00Z',affected:[{package:{ecosystem:'PyPI',name:'Friendly_._Bard'},versions:['1.0']}]});
 assert.deepEqual(result.records[0].packages,['PyPI:friendly-bard']);assert.equal(result.records[0].affected[0].package,'friendly-bard');assert.equal(result.records[0].affected[0].reportedPackage,'Friendly_._Bard');
});

test('OSV retains withdrawn historical invalid PyPI names without weakening active package validation',()=>{
 const raw={id:'MAL-2024-10183',modified:'2024-12-12T11:22:57Z',withdrawn:'2024-12-12T11:22:57Z',affected:[{package:{ecosystem:'PyPI',name:'urlcon-'},versions:['1.0.0']}]};
 const normalized=normalizeIntelligence('OSV',raw).records[0];assert.ok(normalized.withdrawnAt);assert.equal(normalized.affected[0].kind,'OSV_WITHDRAWN_PACKAGE');assert.equal(normalized.affected[0].reportedPackage,'urlcon-');assert.equal((normalized.metadata.withdrawnIdentityIssues as any[])[0].reportedPackage,'urlcon-');
 assert.throws(()=>normalizeIntelligence('OSV',{...raw,withdrawn:undefined}));
});

test('OSV preserves a Git-only affected entry without inventing a registry package',()=>{
 const raw={id:'OSV-GIT-ONLY-FIXTURE',modified:'2026-10-31T00:00:00Z',affected:[{ranges:[{type:'GIT',repo:'https://github.com/example/project',events:[{introduced:'0'},{fixed:'a'.repeat(40)}]}]}]};
 const row=normalizeIntelligence('OSV',raw).records[0];assert.equal(row.purpose,'CANDIDATE');assert.equal(row.affected[0].kind,'OSV_UNSCOPED');assert.equal(row.affected[0].package,undefined);assert.deepEqual(row.affected[0].ranges,raw.affected[0].ranges);assert.equal(row.metadata.unscopedAffectedCount,1);
});

test('OSV wildcard package identities remain explicit ecosystem-wide conditions',()=>{
 const row=normalizeIntelligence('OSV',{id:'OSV-WILDCARD-FIXTURE',modified:'2026-10-31T00:00:00Z',affected:[{package:{ecosystem:'PyPI',name:'*'},ranges:[{type:'ECOSYSTEM',events:[{introduced:'0'},{fixed:'2.0'}]}]}]}).records[0];
 assert.equal(row.affected[0].package,'*');assert.deepEqual(row.packages,['PyPI:*']);
});
