import '../apps/api/node_modules/reflect-metadata';
import {createReadStream, readFileSync, writeFileSync, rmSync, mkdirSync, mkdtempSync} from 'node:fs';
import {createGunzip} from 'node:zlib';
import {createHash, randomBytes} from 'node:crypto';
import {spawnSync} from 'node:child_process';
import assert from 'node:assert/strict';
import {Db} from '../apps/api/src/db';
import {syncVulnerabilityFeed, VulnerabilityFeedsController} from '../apps/api/src/intelligence';
import {prepareNvdMerge} from '../apps/api/src/intelligence-nvd-sync';
import {nvdFeedDocument, parseNvdMeta} from '../apps/api/src/intelligence-nvd-feed';
import {captureRawChunks, recordSourceManifest} from '../apps/api/src/intelligence-artifacts';
import {snapshotSourceProof} from '../apps/api/src/intelligence-snapshot-proof';

const sha = (value: string | Buffer) => createHash('sha256').update(value).digest('hex');
async function main() {
  const year = Number(process.env.NVD_SMOKE_YEAR || 2002); assert.ok([2002, 2026].includes(year));
  const directory = '/workspace/.artifacts/source-artifact-acceptance'; mkdirSync(directory, {recursive: true, mode: 0o700});
  const root = mkdtempSync(directory + '/nvd-combined-'), schema = 'nvd_combined_' + randomBytes(12).toString('hex'), admin = new Db(), url = new URL(process.env.DATABASE_URL!); url.searchParams.set('schema', schema); let db: Db | undefined;
  process.env.INTELLIGENCE_ARTIFACT_DIR = root;
  const started = Date.now(), inputs = '/workspace/.artifacts/intelligence-inputs/', official = JSON.parse(readFileSync('/workspace/.artifacts/results/expansion/nvd-modified-live-original.json', 'utf8'));
  const modifiedProof = JSON.parse(readFileSync('/workspace/' + official.manifestFile, 'utf8')), annualMetaText = readFileSync(inputs + 'nvd-' + year + '.meta', 'utf8');
  async function replay(file: string, text: string, scope: 'ANNUAL' | 'MODIFIED') {
    const meta = parseNvdMeta(text); recordSourceManifest('nvdMeta', {...meta, original: text, sha256OfMeta: sha(text)});
    const input = createReadStream(file), body = input.pipe(createGunzip()), hash = createHash('sha256'), stored = createHash('sha256'); input.on('data', bytes => stored.update(bytes)); input.on('error', error => body.destroy(error));
    const stream: any = {sourceSha256: '', decodedBytes: 0, abort() { input.destroy(); body.destroy(); }};
    async function* chunks() { for await (const part of body) { stream.decodedBytes += part.length; hash.update(part); yield part; } stream.sourceSha256 = hash.digest('hex'); if (scope === 'MODIFIED') assert.equal(stored.digest('hex'), modifiedProof.artifactSha256); }
    stream.chunks = captureRawChunks(chunks()); return nvdFeedDocument(meta, stream, scope);
  }
  try {
    await admin.$executeRawUnsafe('CREATE SCHEMA "' + schema + '"');
    const setup = spawnSync(process.execPath, ['node_modules/prisma/build/index.js', 'migrate', 'deploy'], {env: {...process.env, DATABASE_URL: url.href}, encoding: 'utf8'}); assert.equal(setup.status, 0, setup.stderr); db = new Db({datasourceUrl: url.href});
    const controller = new VulnerabilityFeedsController(db), req = {user: {role: 'ADMIN', email: 'nvd-combined-owned@fixture.test'}}, feed = await controller.create(req, {name: 'Official frozen NVD annual plus modified ' + year, provider: 'NVD', config: {mode: 'YEAR', year, syncMode: 'AUTO'}});
    let annualDownloads = 0, modifiedDownloads = 0;
    const prepare = (client: Db, source: any, current: any, snapshotId: string, leaseId: string) => prepareNvdMerge(client, source, current, snapshotId, leaseId, {fetchAnnual: async () => { annualDownloads++; return replay(inputs + 'nvd-' + year + '.json.gz', annualMetaText, 'ANNUAL'); }, fetchModified: async () => { modifiedDownloads++; return replay('/workspace/' + official.retainedFile, modifiedProof.sourceManifest.nvdMeta.original, 'MODIFIED'); }, fetchMeta: async () => { const proof = modifiedProof.sourceManifest.nvdMeta; recordSourceManifest('nvdMeta', proof); return parseNvdMeta(proof.original); }});
    const sync = () => syncVulnerabilityFeed(db!, feed.id, req.user.email, undefined, {prepareNvdMerge: prepare});
    const first = await sync(); assert.equal(first.snapshot.status, 'COMPLETE', first.snapshot.error || ''); assert.ok(first.snapshot.recordCount >= (year === 2002 ? 6771 : 83392));
    const snapshot = await db.vulnerabilitySnapshot.findUniqueOrThrow({where: {id: first.snapshot.id}, include: {artifact: true}}), proof = await snapshotSourceProof(db, snapshot);
    assert.deepEqual(proof.sourceParts?.map(row => row.role), ['ANNUAL_SOURCE', 'BASELINE_UPDATES']);
    const receipt = await sync(); assert.equal(receipt.snapshot.status, 'UNCHANGED', receipt.snapshot.error || ''); assert.equal(receipt.feed.currentSnapshotId, first.snapshot.id); assert.equal(annualDownloads, 1); assert.equal(modifiedDownloads, 1);
    assert.equal(await db.finding.count(), 0); assert.equal(await db.vulnerabilitySnapshot.count({where: {status: 'STAGING'}}), 0);
    const records = await controller.records(req, feed.id, {page: 1, pageSize: 15}); assert.equal(records.items.length, 15); assert.ok(records.items.every(record => record.purpose === 'CANDIDATE'));
    const result = {at: new Date().toISOString(), year, source: 'Previously frozen genuine official annual and full modified JSON originals; this publication run replays verified retained bytes', liveTransportThisRun: false, records: snapshot.recordCount, sourceParts: proof.sourceParts, merge: (snapshot.sourceManifest as any).nvdMerge, coveredThrough: (snapshot.sourceManifest as any).sync.coveredThrough, unchangedReceipt: true, currentPointerPreserved: true, findingsCreated: 0, annualDownloads, modifiedDownloads, nodeMaxRssKiB: process.resourceUsage().maxRSS, elapsedSeconds: (Date.now() - started) / 1000};
    writeFileSync('/workspace/.artifacts/results/expansion/nvd-' + year + '-combined-snapshot.json', JSON.stringify(result, null, 2)); console.log(JSON.stringify(result));
  } finally { await db?.$disconnect(); await admin.$executeRawUnsafe('DROP SCHEMA "' + schema + '" CASCADE'); await admin.$disconnect(); rmSync(root, {recursive: true, force: true}); }
}
main().catch(error => { console.error(error.stack || error.message); process.exitCode = 1; });
