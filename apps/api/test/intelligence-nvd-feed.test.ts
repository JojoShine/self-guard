import {test} from 'node:test';import assert from 'node:assert/strict';import {jsonArrayFeed} from '../src/intelligence-array-stream';
import {parseNvdMeta} from '../src/intelligence-nvd-feed';
async function* chunks(text:string,size=1){const bytes=Buffer.from(text);for(let i=0;i<bytes.length;i+=size)yield bytes.subarray(i,i+size)}
async function parse(text:string,size=1,limit=1024){const rows=[];for await(const row of jsonArrayFeed(chunks(text,size),'vulnerabilities',limit))rows.push(row);return rows}
test('NVD array feed streams records and retains root metadata before and after the array',async()=>{
 const input={totalResults:2,format:'NVD_CVE',vulnerabilities:[{cve:{id:'CVE-2024-1001',text:'Unicode汉字 and escaped \\" []{}'}},{cve:{id:'CVE-2024-1002',tags:[]}}],startIndex:0,version:'2.0',optional:null};
 const expected=[{key:'totalResults',value:2},{key:'format',value:'NVD_CVE'},{record:input.vulnerabilities[0]},{record:input.vulnerabilities[1]},{key:'startIndex',value:0},{key:'version',value:'2.0'},{key:'optional',value:null}];for(const size of [1,2,7,128,4096])assert.deepEqual(await parse(JSON.stringify(input),size),expected);
 assert.deepEqual(await parse('{"vulnerabilities":[]}'),[]);
 for(const raw of ['','{}','{"vulnerabilities":[{}','{"vulnerabilities":[{},]}','{"vulnerabilities":[null]}','{"vulnerabilities":[],}','{"vulnerabilities":[],"vulnerabilities":[]}','{"vulnerabilities":[]} {}','{"vulnerabilities":[]}\u00a0'])await assert.rejects(parse(raw));
 await assert.rejects(parse('{"vulnerabilities":[{"data":"'+ 'x'.repeat(200)+'"}]}',7,100));
});
test('NVD official meta accepts only bounded sizes, a complete digest and valid publication time',()=>{
 const valid='lastModifiedDate:2026-10-31T03:00:23-04:00\r\nsize:508470458\r\nzipSize:43139989\r\ngzSize:43139853\r\nsha256:'+'A'.repeat(64)+'\r\n';assert.equal(parseNvdMeta(valid).sha256,'a'.repeat(64));assert.equal(parseNvdMeta(valid).size,508470458);
 for(const value of [valid+'size:2\n',valid.replace('508470458','9999999999'),valid.replace('A'.repeat(64),'bad'),valid.replace('2026-10-31T03:00:23-04:00','invalid')])assert.throws(()=>parseNvdMeta(value));
});
