import type {Db} from './db';
import {intelligenceSnapshotFingerprint} from './intelligence-fingerprint';

export async function snapshotFingerprint(db: Db, snapshotId: string, expectedCount?: number) {
  const hashes: (string | null)[] = []; let cursor: string | undefined;
  for (;;) {
    const rows = await db.vulnerabilityRecord.findMany({where: {snapshotId}, select: {id: true, normalizedSha256: true}, orderBy: {id: 'asc'}, take: 1000, ...(cursor ? {cursor: {id: cursor}, skip: 1} : {})});
    hashes.push(...rows.map(row => row.normalizedSha256));
    if (hashes.length > 1000000) throw Error('情报合并快照超过一百万条预算');
    if (rows.length < 1000) break;
    cursor = rows.at(-1)!.id;
  }
  if (expectedCount !== undefined && expectedCount !== hashes.length) throw Error('完整基线记录数量不一致');
  return {recordCount: hashes.length, contentSha256: intelligenceSnapshotFingerprint(hashes)};
}


export async function copySnapshotRecords(db: Db, baseSnapshotId: string, snapshotId: string, expectedCount: number, held: (tx: any) => Promise<void>) {
  let cursor = '', copied = 0;
  for (;;) {
    const page = await db.$transaction(async tx => {
      await held(tx);
      const result = await tx.$queryRaw<{cursor: string | null; count: number}[]>`
        WITH page AS MATERIALIZED (
          SELECT * FROM "VulnerabilityRecord" WHERE "snapshotId"=${baseSnapshotId} AND id>${cursor} ORDER BY id LIMIT 1000
        ), copied AS (
          INSERT INTO "VulnerabilityRecord" (id,"snapshotId","externalId",aliases,summary,details,severity,scores,purpose,affected,packages,"references",metadata,"modifiedAt","withdrawnAt","rawSha256","normalizedSha256")
          SELECT gen_random_uuid()::text,${snapshotId},"externalId",aliases,summary,details,severity,scores,purpose,affected,packages,"references",metadata,"modifiedAt","withdrawnAt","rawSha256","normalizedSha256" FROM page RETURNING id
        ) SELECT (SELECT id FROM page ORDER BY id DESC LIMIT 1) AS cursor, (SELECT count(*)::int FROM copied) AS count`;
      return result[0];
    }, {timeout: 30000});
    copied += page.count;
    if (page.count < 1000) break;
    if (!page.cursor || page.cursor <= cursor) throw Error('完整基线复制游标未前进');
    cursor = page.cursor;
  }
  if (copied !== expectedCount) throw Error('完整基线复制数量不一致');
}
