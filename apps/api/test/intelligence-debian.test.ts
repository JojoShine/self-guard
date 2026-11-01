import {test} from 'node:test';import assert from 'node:assert/strict';
import {jsonObjectEntries,jsonObjectPairs} from '../src/intelligence-json-stream';
import {normalizeDebianPackage} from '../src/intelligence-debian';
import {assessInventory} from '../src/intelligence-match';
async function* chunks(text:string,size=1){const bytes=Buffer.from(text);for(let i=0;i<bytes.length;i+=size)yield bytes.subarray(i,i+size)}
async function entries(text:string,size=1){const rows=[];for await(const row of jsonObjectEntries(chunks(text,size)))rows.push(row);return rows}
test('large-source parser retains Unicode, escaped delimiters and nested records across arbitrary chunk boundaries',async()=>{
 const value={'软件"':{description:'合法 { } \\ " 文本',values:[1,{},'x']},second:{}};
 for(const size of [1,2,7,64,1024])assert.deepEqual(await entries(JSON.stringify(value),size),Object.entries(value));
 for(const value of ['','{"a":{}','{"a":{},}','{"a":{},"a":{}}','{} {}','{"a":null}','{"a":{]}}','{}\u00a0'])await assert.rejects(entries(value));
 async function* invalid(){yield Buffer.from([123,34,255,34,58,123,125,125])}await assert.rejects(async()=>{for await(const _ of jsonObjectEntries(invalid())){}});
 await assert.rejects(async()=>{for await(const _ of jsonObjectEntries(chunks('{"a":{"x":"'+ 'x'.repeat(40)+'"}}'),32)){}});
});
test('Debian streams individual advisories without buffering an entire large package',async()=>{
 const raw={linux:{'CVE-2024-1001':{description:'一'},'CVE-2024-1002':{description:'二'}},empty:{},openssl:{'CVE-2024-1001':{description:'三'}}},actual=[];
 for await(const value of jsonObjectPairs(chunks(JSON.stringify(raw),3),64))actual.push(value);
 assert.deepEqual(actual,[[['linux','CVE-2024-1001'],{description:'一'}],[['linux','CVE-2024-1002'],{description:'二'}],[['openssl','CVE-2024-1001'],{description:'三'}]]);
 for(const value of ['{"linux":{"x":{},}}','{"linux":{"x":{},"x":{}}}','{"linux":{"x":{}}}{"other":{}}'])await assert.rejects(async()=>{for await(const _ of jsonObjectPairs(chunks(value))) {}});
});
test('Debian vendor triage distinguishes fixed, open, unaffected and undetermined without inventing scores',()=>{
 const raw:any={};for(const [id,status,fixed]of [['CVE-2024-1001','resolved','1:2.0-1'],['CVE-2024-1002','open',undefined],['CVE-2024-1003','resolved','0'],['CVE-2024-1004','undetermined',undefined]])raw[id]={description:'实际厂商说明',scope:'remote',releases:{bookworm:{status,fixed_version:fixed,urgency:'high',repositories:{bookworm:'1:2.0-1'}}}};
 raw['CVE-2024-1005']={description:'其他分支',releases:{trixie:{status:'open'}}};
 const records=normalizeDebianPackage('sample',raw,'bookworm');assert.equal(records.length,4);assert.ok(records.every(r=>r.severity===null&&r.scores.length===0));assert.equal(records[0].affected[0].ecosystem,'Debian:12');assert.equal(records[2].affected[0].status,'NOT_AFFECTED');assert.equal(records[3].affected[0].status,'UNKNOWN');
 const inventory={distribution:{id:'debian',versionId:'12'},distributionCollection:{complete:true},packageCollection:{complete:true},packages:[{name:'libsample1',version:'1:1.0-1+b1',origin:'sample',sourceVersion:'1:1.0-1',architecture:'amd64'}]};
 const assessed=assessInventory(inventory,records.map(record=>({source:{feedId:'debian',snapshotId:'fixed',provider:'DEBIAN',version:'digest',sourceSha256:'a'.repeat(64),stale:false},record})));
 assert.deepEqual(assessed.findings.map(f=>f.identity),['CVE-2024-1001','CVE-2024-1002']);assert.equal(assessed.coverage.status,'INCONCLUSIVE');assert.equal(assessed.findings[0].evidence.applicability[0].actual,'1:1.0-1');assert.equal(assessed.findings[0].evidence.applicability[0].fixed,'1:2.0-1');
 const fixedInventory={...inventory,packages:[{...inventory.packages[0],sourceVersion:'1:2.0-1'}]};assert.deepEqual(assessInventory(fixedInventory,records.slice(0,1).map(record=>({source:{feedId:'debian',snapshotId:'fixed',provider:'DEBIAN',version:'digest',sourceSha256:'a'.repeat(64),stale:false},record}))).findings,[]);
});
