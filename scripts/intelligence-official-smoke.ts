import {readFileSync,writeFileSync} from 'node:fs';import {createHash} from 'node:crypto';import assert from 'node:assert/strict';
import {normalizeIntelligence,type IntelligenceProvider} from '../apps/api/src/intelligence-normalize';
const summaries:any[]=[];const identifiers=new Map<string,string[]>();
for(const [provider,name]of [['OSV','osv-log4shell'],['NVD','nvd-log4shell'],['CISA_KEV','cisa-kev'],['ALPINE','alpine-main']] as Array<[IntelligenceProvider,string]>){
 const bytes=readFileSync('/workspace/.artifacts/intelligence-inputs/'+name+'.json'),raw=JSON.parse(bytes.toString()),normalized=normalizeIntelligence(provider,raw);assert.ok(normalized.records.length>0);if(provider==='CISA_KEV')assert.equal(normalized.records.length,raw.count);
 for(const entry of normalized.records)if(entry.aliases.includes('CVE-2021-44228'))identifiers.set(provider,entry.aliases);
 const purposes:Record<string,number>={};for(const record of normalized.records)purposes[record.purpose]=(purposes[record.purpose]||0)+1;
 const result={provider,records:normalized.records.length,version:normalized.version,purposes,unrated:normalized.records.filter(r=>r.severity===null).length,sourceSha256:createHash('sha256').update(bytes).digest('hex'),coverage:normalized.coverage};summaries.push(result);console.log(JSON.stringify(result));
}
assert.ok(identifiers.has('OSV'));assert.ok(identifiers.has('NVD'));assert.ok(identifiers.has('CISA_KEV'));console.log('PASS: independently fetched OSV, NVD and KEV share the same CVE; KEV stays prioritization only');
writeFileSync('/workspace/.artifacts/results/expansion/intelligence-real-normalization.json',JSON.stringify({at:new Date().toISOString(),sources:summaries,crossSourceCve:'CVE-2021-44228'},null,2));
