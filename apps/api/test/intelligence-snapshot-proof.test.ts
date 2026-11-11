import {test} from 'node:test';
import assert from 'node:assert/strict';
import {pinScanSources, assessPinnedInventory} from '../src/scan-intelligence';

const sha = (letter: string) => letter.repeat(64), config = {mode: 'ECOSYSTEM', ecosystem: 'Go', syncMode: 'AUTO'}, baseId = '00000000-0000-4000-8000-000000000001';
const base: any = {id: baseId, feedId: 'feed', status: 'COMPLETE', config, sourceUrl: 'https://storage.googleapis.com/osv-vulnerabilities/Go/all.zip', sourceSha256: sha('a'), artifactSha256: sha('a'), contentSha256: sha('b'), artifact: {encoding: 'ZIP'}, normalizerVersion: 'selfguard-intelligence-v7'};
const current: any = {id: '00000000-0000-4000-8000-000000000002', feedId: 'feed', status: 'COMPLETE', config, version: 'OSV/Go@index-fixed', normalizerVersion: base.normalizerVersion, sourceUrl: 'https://storage.googleapis.com/osv-vulnerabilities/Go/modified_id.csv', sourceSha256: sha('c'), artifactSha256: sha('d'), contentSha256: sha('e'), license: 'Original advisory licences', sourceManifest: {sync: {mode: 'DELTA', packageFormat: 'selfguard-osv-delta-v1', baseSnapshotId: baseId, baseArtifactSha256: base.artifactSha256, baseContentSha256: base.contentSha256}, normalization: {activeUnscopedAffected: 0, coveredEcosystems: ['Go']}}};
function fixture(root: any = base) {
  const feed = {id: 'feed', name: 'Owned composite source', provider: 'OSV', enabled: true, currentSnapshotId: current.id, lastSuccessAt: new Date(), configHash: 'frozen', staleAfterHours: 72};
  const record = {id: 'record', externalId: 'GO-1', aliases: ['GO-1'], purpose: 'PACKAGE', summary: 'Inherited actual root fact', details: 'Inherited from full root', rawSha256: sha('f'), withdrawnAt: null, scores: [], metadata: {}, affected: [{kind: 'OSV_PACKAGE', ecosystem: 'Go', package: 'fixture.test/example', scheme: 'SEMVER', versions: ['1.0.0'], ranges: []}]};
  return {vulnerabilityFeed: {findMany: async () => [feed], findUnique: async () => feed}, vulnerabilitySnapshot: {findFirst: async (query: any) => query.where.id === baseId ? root : current}, vulnerabilityRecord: {findMany: async (query: any) => query.where.purpose === 'PACKAGE' ? [record] : []}};
}
test('scan pins and hydrated findings retain both full-root and incremental original identities', async () => {
  const db = fixture(), pins = await pinScanSources(db, ['feed']);
  assert.equal(pins[0].contentSha256, current.contentSha256); assert.equal(pins[0].artifactSha256, current.artifactSha256);
  assert.deepEqual(pins[0].sourceParts?.map(row => [row.role, row.snapshotId, row.sourceSha256]), [['COMPLETE_BASE', base.id, base.sourceSha256], ['VERIFIED_DELTA', current.id, current.sourceSha256]]);
  const result = await assessPinnedInventory(db, {components: [{ecosystem: 'Go', name: 'fixture.test/example', version: '1.0.0'}], componentCollection: {complete: true}}, pins);
  assert.equal(result.findings.length, 1); assert.deepEqual(result.findings[0].evidence.sources[0].sourceParts, pins[0].sourceParts);
});
test('composite proof refuses a missing, mismatched, changed-scope or unfinished root', async () => {
  for (const root of [null, {...base, status: 'FAILED'}, {...base, artifactSha256: sha('f')}, {...base, config: {...config, ecosystem: 'npm'}}, {...base, contentSha256: sha('f')}]) {
    await assert.rejects(() => pinScanSources(fixture(root), ['feed']), /基线|来源/);
  }
});

test('NVD full baseline can be pinned and hydrated through the real snapshot relation projection',async()=>{
 const config={mode:'YEAR',year:2026,syncMode:'AUTO'},rootId='nvd-root',annualId='nvd-annual',artifact={encoding:'GZIP_JSON'};
 const annual={id:annualId,feedId:'nvd-feed',status:'COMPLETE',config,normalizerVersion:'selfguard-intelligence-v7',sourceSha256:sha('a'),artifactSha256:sha('b'),contentSha256:sha('c'),sourceUrl:'https://nvd.nist.gov/annual',artifact,sourceManifest:{sync:{role:'ANNUAL_COMPONENT',parentSnapshotId:rootId}}};
 const root={...annual,id:rootId,version:'2026/fixed',sourceSha256:sha('d'),artifactSha256:sha('e'),contentSha256:sha('f'),sourceUrl:'https://nvd.nist.gov/modified',sourceManifest:{sync:{strategy:'NVD_FULL_WITH_MODIFIED',annualSnapshotId:annualId,annualArtifactSha256:annual.artifactSha256,annualContentSha256:annual.contentSha256}}};
 const feed={id:'nvd-feed',name:'NVD official composite',provider:'NVD',enabled:true,configHash:'fixed',currentSnapshotId:rootId,lastSuccessAt:new Date(),staleAfterHours:72};
 const db={vulnerabilityFeed:{findMany:async()=>[feed],findUnique:async()=>feed},vulnerabilitySnapshot:{findFirst:async(query:{where:{id:string};include?:{artifact?:boolean}})=>{const selected=query.where.id===rootId?root:annual;return{...selected,artifact:query.include?.artifact?selected.artifact:undefined}}},vulnerabilityRecord:{findMany:async()=>[]}};
 const pins=await pinScanSources(db,[feed.id]);assert.equal(pins[0].sourceParts?.length,2);const result=await assessPinnedInventory(db,{components:[{ecosystem:'npm',name:'example',version:'1.0.0'}],componentCollection:{complete:true}},pins);assert.equal(result.coverage.status,'INCONCLUSIVE');
});
