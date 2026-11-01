import { test } from "node:test";
import assert from "node:assert/strict";
import { Db } from "../src/db";
import { Platform } from "../src/platform";
import { Lifecycle } from "../src/lifecycle";
test(
  "real database lifecycle expires acceptance and claims due schedule once",
  { skip: !process.env.TEST_API_URL },
  async () => {
    const db = new Db();
    const p = new Platform(db);
    const lifecycle = new Lifecycle(db, p);
    const mark = Date.now().toString();
    try {
      const asset = await db.asset.create({
        data: {
          hostname: "lifecycle-" + mark,
          os: "linux",
          inventory: { packages: [{ name: "fixture", version: "1" }] },
        },
      });
      const finding = await db.finding.create({
        data: {
          dedupKey: "lifecycle-" + mark,
          externalId: mark,
          title: "Expired acceptance fixture",
          kind: "RISK",
          severity: "LOW",
          source: "test",
          evidence: "test",
          status: "ACCEPTED",
          expiresAt: new Date(Date.now() - 1000),
        },
      });
      const rule = await db.rule.create({
        data: {
          name: "Scheduled fixture " + mark,
          kind: "VULNERABILITY",
          severity: "MEDIUM",
          enabled: true,
          intervalSeconds: 60,
          nextRunAt: new Date(Date.now() - 1000),
          config: {
            package: "fixture",
            affectedVersion: "1",
            os: "linux",
            advisory: "test only",
          },
        },
      });
      await Promise.all([lifecycle.sweep(), lifecycle.sweep()]);
      assert.equal(
        (await db.finding.findUniqueOrThrow({ where: { id: finding.id } }))
          .status,
        "OPEN",
      );
      assert.equal(
        await db.evaluation.count({
          where: { ruleId: rule.id, assetId: asset.id, matched: true },
        }),
        1,
      );
      const next = (await db.rule.findUniqueOrThrow({ where: { id: rule.id } }))
        .nextRunAt;
      assert.ok(next && next > new Date());
      await db.rule.update({
        where: { id: rule.id },
        data: { enabled: false },
      });
    } finally {
      await db.$disconnect();
    }
  },
);
