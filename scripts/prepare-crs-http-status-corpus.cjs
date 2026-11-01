// Preserve original fixture bytes and status assertions. This only prepares the
// bounded native HTTP replay input; it does not run a server or change a policy.
const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict'),{createHash}=require('node:crypto'),{request}=require('./crs-ftw-request.cjs');
const root=path.resolve(__dirname,'..'),folder=path.join(root,'.artifacts/results/expansion'),corpus=JSON.parse(fs.readFileSync(path.join(folder,'crs-full-corpus.json'))),index=JSON.parse(fs.readFileSync(path.join(folder,'crs-full-selection-final-index.json'))),byId=new Map(index.rules.map(rule=>[rule.id,rule]));
assert.equal(corpus.archiveSha256,'0539e66e7627fe71c160a644d8fb7ab6e450d53c9de208be5f95a35c70e1a154');assert.equal(corpus.errors.length,0);
const cases=[],excluded=[];
for(const file of corpus.files){const document=file.document;if(!document)continue;
 const original=fs.readFileSync(path.join(root,'.artifacts/crs-v4.25.1',file.path));assert.equal(createHash('sha256').update(original).digest('hex'),file.sha256,'Original fixture changed: '+file.path);
 for(const test of document.tests||[])for(const [stage,entry]of(test.stages||[]).entries()){
  if(entry.output?.status===undefined)continue;
  const declared=String(document.rule_id),fallback=path.basename(file.path,'.yaml'),ruleId=byId.has(declared)?declared:byId.has(fallback)?fallback:declared;
  let rule=byId.get(ruleId);if(!rule&&(entry.output?.log?.no_expect_ids||[]).map(String).includes(ruleId)&&!entry.output?.log?.expect_ids?.length)rule={phase:2,paranoiaLevel:1};
  const identity={file:file.path,fileSha256:file.sha256,ruleId,testId:test.test_id,stage};
  if(!rule||rule.phase>2||rule.paranoiaLevel>1||rule.inactiveByConfiguration){excluded.push({...identity,reason:!rule?'RULE_NOT_INDEXED':rule.phase>2?'OUTBOUND_PHASE':rule.paranoiaLevel>1?'HIGHER_PARANOIA':'INACTIVE_CONFIGURATION'});continue}
  const expectedStatuses=Array.isArray(entry.output.status)?entry.output.status:[entry.output.status];assert.ok(expectedStatuses.length&&expectedStatuses.length<=10&&expectedStatuses.every(status=>Number.isInteger(status)&&status>=100&&status<=599),'Unsupported original status assertion');
  cases.push({...identity,requestBase64:request(entry.input||{}).toString('base64'),expectedStatuses,threshold:ruleId==='949110'?5:10000});
 }
}
assert.ok(cases.length>0&&cases.length<=100);
const files=JSON.parse(fs.readFileSync(path.join(folder,'crs-current-input.json'))).files;
files.push({name:'crs-setup.conf',source:fs.readFileSync(path.join(root,'third_party/crs/selfguard-inbound-PL1.conf'),'utf8')},{name:'000-regression-limits.conf',source:fs.readFileSync(path.join(root,'third_party/crs/selfguard-regression-limits.conf'),'utf8')});
const name=process.env.CRS_HTTP_RUN_NAME||'native';assert.match(name,/^[a-z0-9-]{1,60}$/);const output=path.join(folder,'crs-'+name+'-http-input.json');fs.writeFileSync(output,JSON.stringify({archiveSha256:corpus.archiveSha256,files,cases}),{mode:0o600});fs.writeFileSync(path.join(folder,'crs-'+name+'-http-selection.json'),JSON.stringify({archiveSha256:corpus.archiveSha256,selected:cases.length,cases:cases.map(({requestBase64,...row})=>({...row,requestSha256:createHash('sha256').update(Buffer.from(requestBase64,'base64')).digest('hex')})),excluded},null,2),{mode:0o600});console.log(JSON.stringify({prepared:true,selectedOriginalStatusAssertions:cases.length,excluded:excluded.length,input:path.relative(root,output),runtimePublished:false}));
