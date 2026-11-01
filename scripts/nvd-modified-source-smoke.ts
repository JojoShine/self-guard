import '../apps/api/node_modules/reflect-metadata';
import {constants, copyFileSync, existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync} from 'node:fs';
import {join} from 'node:path';
import {createHash} from 'node:crypto';
import assert from 'node:assert/strict';
import {withRawArchive, artifactPath} from '../apps/api/src/intelligence-artifacts';
import {downloadNvdModifiedPart} from '../apps/api/src/intelligence-nvd-part';
import {readNvdOriginalVersions} from '../apps/api/src/intelligence-nvd-original';

async function main() {
  const parent = '/workspace/.artifacts/source-artifact-acceptance'; mkdirSync(parent, {recursive: true, mode: 0o700});
  const root = mkdtempSync(join(parent, 'nvd-modified-')), started = Date.now();
  try { await withRawArchive(256 * 1024 * 1024, async () => {
    const feed = {id: 'public-nvd-source-acceptance', provider: 'NVD', config: {mode: 'YEAR', year: 2026, syncMode: 'AUTO'}}, part = await downloadNvdModifiedPart(feed);
    assert.ok(part.versions.totalRecords > 0); assert.ok(part.versions.records.size > 0);
    const reread = await readNvdOriginalVersions(part.snapshot, 2026, 'MODIFIED'); assert.deepEqual(reread.records, part.versions.records); assert.deepEqual(reread.digests, part.versions.digests);
    const source = artifactPath(root, part.snapshot.artifactSha256), name = 'nvd-modified-retained-' + part.snapshot.artifactSha256, retained = '/workspace/.artifacts/intelligence-inputs/' + name + '.json.gz';
    if (!existsSync(retained)) { copyFileSync(source, retained, constants.COPYFILE_EXCL); }
    assert.ok(lstatSync(retained).isFile() && !lstatSync(retained).isSymbolicLink()); assert.equal(createHash('sha256').update(readFileSync(retained)).digest('hex'), part.snapshot.artifactSha256);
    const proof = part.snapshot.sourceManifest as any, proofFile = '/workspace/.artifacts/intelligence-inputs/' + name + '-' + proof.nvdMeta.sha256OfMeta + '.manifest.json';
    if (!existsSync(proofFile)) writeFileSync(proofFile, JSON.stringify({sourceUrl: part.snapshot.sourceUrl, sourceSha256: part.snapshot.sourceSha256, artifactSha256: part.snapshot.artifactSha256, artifact: part.snapshot.artifact, sourceManifest: part.snapshot.sourceManifest}, null, 2), {flag: 'wx', mode: 0o600});
    const result = {at: new Date().toISOString(), sourceUrl: part.snapshot.sourceUrl, sourceSha256: part.snapshot.sourceSha256, artifactSha256: part.snapshot.artifactSha256, retainedFile: retained.replace('/workspace/', ''), manifestFile: proofFile.replace('/workspace/', ''), originalBytes: proof.nvdMeta.size, retainedGzipBytes: part.snapshot.artifact.size, upstreamGzipBytes: proof.nvdMeta.gzSize, records: part.versions.totalRecords, selectedYear: 2026, selectedYearRecords: part.versions.records.size, coveredThrough: part.versions.coveredThrough, fullOriginalReverified: true, liveTransport: true, nodeMaxRssKiB: process.resourceUsage().maxRSS, elapsedSeconds: (Date.now() - started) / 1000, meaning: 'Read-only genuine official modified source; all original JSON bytes retained and verified. This alone does not complete annual-plus-modified baseline publication or create asset risks.'};
    writeFileSync('/workspace/.artifacts/results/expansion/nvd-modified-live-original.json', JSON.stringify(result, null, 2), {mode: 0o600}); console.log(JSON.stringify(result));
  }, {root}); } finally { rmSync(root, {recursive: true, force: true}); }
}
main().catch(error => { console.error(error.message); process.exitCode = 1; });
