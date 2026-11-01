import { test } from "node:test";
import assert from "node:assert/strict";
import { Db } from "../src/db";
import { Platform } from "../src/platform";
import { GovernanceController, approvalPolicyInput, assertTaskApproval, retentionInput } from "../src/governance";

test("approval and retention configuration reject unsafe or unknown values", () => {
  assert.equal(approvalPolicyInput.safeParse({ approverRoles: [] }).success, false);
  assert.equal(approvalPolicyInput.safeParse({ approverRoles: ["ANALYST"], allowSelfApproval: false }).success, true);
  assert.equal(approvalPolicyInput.safeParse({ approverRoles: ["ROOT"] }).success, false);
  assert.equal(retentionInput.safeParse({ auditDays: 0 }).success, false);
});

test("real database governance enforces policy, notification isolation, import retry and retention boundaries", { skip: !process.env.GOVERNANCE_TEST_ISOLATED }, async () => {
  assert.match(process.env.DATABASE_URL || "", /[?&]schema=governance_test_[a-zA-Z0-9_]+(?:&|$)/, "Retention test requires an isolated governance_test_ schema");
  const db = new Db();
  const g = new GovernanceController(db, new Platform(db));
  const mark = Date.now().toString();
  const previous = await db.setting.findMany({ where: { key: { in: ["approval-policy", "retention"] } } });
  const userIds: string[] = [];
  const notificationIds: string[] = [];
  const batchIds: string[] = [];
  let findingId: string | undefined;
  try {
    const admin = await db.user.create({ data: { email: `governance-admin-${mark}@test.local`, name: "Test admin", passwordHash: "unused", role: "ADMIN" } });
    const analyst = await db.user.create({ data: { email: `governance-analyst-${mark}@test.local`, name: "Test analyst " + mark, passwordHash: "unused", role: "ANALYST" } });
    const viewer = await db.user.create({ data: { email: `governance-viewer-${mark}@test.local`, name: "Test viewer", passwordHash: "unused", role: "VIEWER" } });
    userIds.push(admin.id, analyst.id, viewer.id);
    const adminReq = { user: admin }, analystReq = { user: analyst }, viewerReq = { user: viewer };
    await assert.rejects(() => g.setApprovalPolicy(viewerReq, { approverRoles: ["VIEWER"], allowSelfApproval: true }));
    await g.setApprovalPolicy(adminReq, { approverRoles: ["ANALYST"], allowSelfApproval: false });
    await assert.rejects(() => assertTaskApproval(db, { requestedBy: analyst.email }, analyst.email), /自批/);
    await assert.rejects(() => assertTaskApproval(db, { requestedBy: viewer.email }, admin.email), /权限/);
    await assertTaskApproval(db, { requestedBy: viewer.email }, analyst.email);
    const owned = await db.notification.create({ data: { userId: analyst.id, title: "Only analyst", resource: "tasks" } });
    notificationIds.push(owned.id);
    await assert.rejects(() => g.readNotification(viewerReq, owned.id));
    assert.equal((await g.readNotification(analystReq, owned.id)).readAt instanceof Date, true);
    assert.equal((await g.notifications(viewerReq, {})).items.length, 0);
    const finding = await db.finding.create({ data: { dedupKey: "governance-" + mark, externalId: mark, title: "Targeted critical finding", kind: "RISK", severity: "CRITICAL", source: "test", evidence: "fixture", owner: analyst.name } });
    findingId = finding.id;
    await g.setNotificationSettings(analystReq, { approvals: false, taskFailures: false });
    await g.syncNotifications(analystReq);
    await g.syncNotifications(analystReq);
    assert.equal(await db.notification.count({ where: { userId: analyst.id, resourceId: finding.id } }), 1);
    const failed = await g.createImport(analystReq, { items: [{ invalid: true }] });
    batchIds.push(failed.id);
    assert.equal(failed.status, "FAILED");
    await assert.rejects(() => g.retryImport(viewerReq, failed.id, {}));
    const retried = await g.retryImport(analystReq, failed.id, { items: [{ externalId: mark, title: "Imported fixture", kind: "ALERT", severity: "LOW", source: "governance-test", evidence: "fixture" }] });
    assert.equal(retried.status, "SUCCEEDED");
    await assert.rejects(() => g.retryImport(analystReq, failed.id, {}), /重试/);
    const expired = await db.notification.create({ data: { userId: viewer.id, title: "expired", resource: "test", createdAt: new Date(Date.now() - 3 * 86400000) } });
    notificationIds.push(expired.id);
    await g.setRetention(adminReq, { notificationDays: 1 });
    const preview = await g.previewRetention(adminReq);
    assert.ok(preview.counts.notifications >= 1);
    assert.ok(await db.notification.findUnique({ where: { id: expired.id } }));
    await assert.rejects(() => g.purgeRetention(viewerReq, { confirm: true }));
    await assert.rejects(() => g.purgeRetention(adminReq, { confirm: false }));
    const purged = await g.purgeRetention(adminReq, { confirm: true });
    assert.ok(purged.deleted.notifications >= 1);
    assert.equal(await db.notification.findUnique({ where: { id: expired.id } }), null);
    assert.ok(await db.notification.findUnique({ where: { id: owned.id } }));
  } finally {
    await db.notification.deleteMany({ where: { OR: [{ userId: { in: userIds } }, { id: { in: notificationIds } }] } });
    await db.importBatch.deleteMany({ where: { id: { in: batchIds } } });
    await db.finding.deleteMany({ where: { OR: [{ id: findingId || "none" }, { externalId: mark, source: "governance-test" }] } });
    await db.setting.deleteMany({ where: { key: { in: ["approval-policy", "retention", ...userIds.map(id => "notifications:" + id)] } } });
    for (const old of previous) await db.setting.create({ data: old });
    await db.user.deleteMany({ where: { id: { in: userIds } } });
    await db.$disconnect();
  }
});
