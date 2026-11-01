// Focused replay of the frozen Cookie-name and large-form compatibility gaps.
const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict'),crypto=require('node:crypto'),{spawnSync}=require('node:child_process');
const {request}=require('./crs-ftw-request.cjs');
const binary=path.resolve(process.env.CRS_COOKIE_BINARY||'.artifacts/bin/waf-cookie-spaces'),label=process.env.CRS_COOKIE_LABEL||'candidate';assert.match(label,/^[a-z0-9-]{1,40}$/);
const corpus=JSON.parse(fs.readFileSync('.artifacts/results/expansion/crs-full-corpus.json'));assert.equal(corpus.archiveSha256,'0539e66e7627fe71c160a644d8fb7ab6e450d53c9de208be5f95a35c70e1a154');
const files=JSON.parse(fs.readFileSync('.artifacts/results/expansion/crs-current-input.json')).files;
for(const name of ['selfguard-inbound-PL1.conf','selfguard-regression-limits.conf'])files.push({name:name.includes('limits')?'000-regression-limits.conf':'crs-setup.conf',source:fs.readFileSync('third_party/crs/'+name,'utf8')});
const rows=[];
for(const [ruleId,testId]of [['933100',89],['941110',8],['920390',1]]){
 const file=corpus.files.find(row=>String(row.document?.rule_id)===ruleId);assert.ok(file);
 const test=file.document.tests.find(row=>row.test_id===testId);assert.equal(test.stages.length,1);
 const stage=test.stages[0],run=spawnSync('docker',['run','--rm','-i','--network','none','--read-only','--cpus','2','--memory','512m','--pids-limit','64','--user','10001:10001','-v',binary+':/waf:ro','--entrypoint','/waf','selfguard-waf-toolchain:1.27.3-pcre2','--test-seclang'],{input:JSON.stringify({files,requestBase64:request(stage.input).toString('base64'),threshold:10000}),encoding:'utf8',timeout:15000,maxBuffer:4<<20});
 assert.equal(run.status,0,run.stderr||run.error?.message);const result=JSON.parse(run.stdout),expected=stage.output.log.expect_ids.map(String);
 rows.push({file:file.path,fileSha256:file.sha256,ruleId,testId,passed:!result.workerError&&expected.every(id=>result.matches?.includes(id)),matches:result.matches||[],failureKind:result.failureKind||null});
}
const report={at:new Date().toISOString(),archiveSha256:corpus.archiveSha256,engineSha256:crypto.createHash('sha256').update(fs.readFileSync(binary)).digest('hex'),scope:'Only two frozen Cookie-name and one large-form rule-ID cases; not a full corpus or performance acceptance',runtimePublished:false,rows};
fs.writeFileSync('.artifacts/results/expansion/crs-cookie-spaces-'+label+'.json',JSON.stringify(report,null,2));
assert.ok(rows.every(row=>row.passed),JSON.stringify(rows));console.log('PASS three frozen request compatibility samples matched their original CRS rule IDs');
