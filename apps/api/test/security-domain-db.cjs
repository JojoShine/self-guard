const assert=require('node:assert/strict');
const fs=require('node:fs');
const {Db}=require('../dist/db');
const {Platform}=require('../dist/platform');

async function main(){
 assert.equal(process.env.SELFGUARD_DOMAIN_ISOLATED,'yes','Only run in a disposable P1 test database');
 const db=new Db(),p=new Platform(db);
 try{
  // Apply the real additive migration to a minimal pre-domain legacy table.
  const sql=fs.readFileSync('prisma/migrations/20261105120000_finding_security_domain/migration.sql','utf8');
  await db.$transaction(async tx=>{
   await tx.$executeRawUnsafe('CREATE SCHEMA legacy_domain');
   await tx.$executeRawUnsafe('SET LOCAL search_path TO legacy_domain');
   await tx.$executeRawUnsafe('CREATE TABLE "Finding" (id text PRIMARY KEY, source text NOT NULL, "createdAt" timestamp NOT NULL DEFAULT now())');
   await tx.$executeRawUnsafe("INSERT INTO \"Finding\" (id,source) VALUES ('database','database-security'),('cve','vulnerability'),('log','agent-log'),('unknown','custom')");
   for(const statement of sql.split(';').map(s=>s.trim()).filter(Boolean))await tx.$executeRawUnsafe(statement);
   const rows=await tx.$queryRawUnsafe('SELECT id,"securityDomain"::text AS domain FROM "Finding" ORDER BY id');
   assert.deepEqual(rows,[{id:'cve',domain:'NETWORK'},{id:'database',domain:'DATA'},{id:'log',domain:'UNCLASSIFIED'},{id:'unknown',domain:'UNCLASSIFIED'}]);
  });
  const a=await db.asset.create({data:{hostname:'domain-a',os:'linux',business:'a'}}),b=await db.asset.create({data:{hostname:'domain-b',os:'linux',business:'b'}});
  const finding=(externalId,source,assetId=a.id)=>({externalId,source,assetId,title:externalId,kind:'ALERT',severity:'HIGH',evidence:'{}'});
  const ingest=(row,config)=>db.$transaction(tx=>p.ingest(tx,row,undefined,config));
  const network=await ingest(finding('network','vulnerability'));
  assert.equal(network.securityDomain,'NETWORK');
  await db.finding.update({where:{id:network.id},data:{status:'CLOSED'}});
  const reopened=await ingest(finding('network','vulnerability'));
  assert.equal(reopened.id,network.id);assert.equal(reopened.dedupKey,network.dedupKey);
  assert.equal(reopened.status,'OPEN');assert.equal(reopened.occurrences,2);
  const data=await ingest(finding('data','database-security'));
  assert.equal(data.securityDomain,'DATA');
  const unknown=await ingest(finding('unknown','agent-log'));
  assert.equal(unknown.securityDomain,'UNCLASSIFIED');
  assert.equal((await ingest(finding('unknown','agent-log'),{type:'DATABASE_AUTH'})).securityDomain,'DATA');
  const replay=await ingest(finding('unknown','agent-log'));
  assert.equal(replay.securityDomain,'DATA');assert.equal(replay.occurrences,3);assert.equal(replay.id,unknown.id);
  const concurrent=await Promise.all([ingest(finding('unknown','agent-log')),ingest(finding('unknown','agent-log'))]);
  assert.ok(concurrent.every(r=>r.id===unknown.id&&r.securityDomain==='DATA'));
  assert.equal((await db.finding.findUniqueOrThrow({where:{id:unknown.id}})).occurrences,5);
  await assert.rejects(()=>ingest({...finding('forged','custom'),securityDomain:'DATA'}));
  await ingest(finding('private','vulnerability',b.id));
  const viewer={role:'VIEWER',dataScope:{restricted:true,businesses:['a'],assetIds:[],databaseInstanceIds:[]}};
  const list=await p.list('findings',{securityDomain:'NETWORK'},viewer);
  assert.equal(list.total,1);assert.equal(list.items[0].id,network.id);
  assert.equal((await p.list('findings',{securityDomain:'DATA'},viewer)).total,2);
  await assert.rejects(()=>p.list('findings',{securityDomain:'bad'},viewer));
  await assert.rejects(()=>p.list('assets',{securityDomain:'DATA'},viewer));
  const incident=await db.incident.create({data:{title:'mixed',severity:'HIGH',assetIds:[a.id],links:{create:[{findingId:network.id},{findingId:data.id}]}}});
  const empty=await db.incident.create({data:{title:'legacy-unclassified',severity:'LOW'}});
  for(const domain of ['NETWORK','DATA']){
   const result=await p.discoveries({securityDomain:domain},viewer);
   assert.ok(result.items.some(r=>r.id===incident.id));
   assert.ok(!result.items.some(r=>r.title==='private'));
   assert.equal(result.total,result.items.length);
  }
  const unclassified=await p.discoveries({securityDomain:'UNCLASSIFIED'});
  assert.ok(unclassified.items.some(r=>r.id===empty.id));
  assert.equal((await p.discoveries({securityDomain:'DATA',pageSize:1},viewer)).total,3);
  assert.equal((await p.discoveries({securityDomain:'DATA',pageSize:1},viewer)).items.length,1);
  const privateInstance=await db.databaseInstance.create({data:{name:'private-instance',stableKey:'private-instance',engine:'mysql',owner:'DBA',business:'private',hostIds:[a.id]}});
  const privateFinding=await ingest({...finding('private-instance-finding','database-security'),instanceId:privateInstance.id});
  const privateIncident=await db.incident.create({data:{title:'host-visible-instance-private',severity:'HIGH',assetIds:[a.id],links:{create:[{findingId:privateFinding.id}]}}});
  assert.ok(!(await p.list('findings',{securityDomain:'DATA'},viewer)).items.some(r=>r.id===privateFinding.id));
  assert.ok(!(await p.discoveries({securityDomain:'DATA'},viewer)).items.some(r=>r.id===privateIncident.id));
  await assert.rejects(()=>p.get('incidents',privateIncident.id,viewer));
  console.log('Domain migration/ingest/replay/filter/scope/mixed-incident checks passed');
 }finally{await db.$disconnect();}
}
main().catch(e=>{console.error(e.message);process.exitCode=1;});
