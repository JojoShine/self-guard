import { test } from "node:test";
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { Db } from "../src/db";
import { assertTaskApproval } from "../src/governance";

const base = process.env.TEST_API_URL;

test("real HTTP/database batch execution, windows, archived agents and approval integration", { skip: !base }, async (t) => {
  const db = new Db();
  const prefix = "batch-review-" + randomUUID();
  const assets: string[] = [], tasks: string[] = [], batches: string[] = [], users: string[] = [];
  let token = "";
  async function call(path: string, method = "GET", body?: unknown, auth = token) {
    const response = await fetch(base + path, {
      method,
      headers: { "content-type": "application/json", ...(auth ? { authorization: "Bearer " + auth } : {}) },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    return { status: response.status, data: await response.json() };
  }
  async function agent(label: string) {
    const response = await call("/agent/enroll", "POST", { hostname: prefix + label, os: "linux", identity: prefix + label }, process.env.ENROLLMENT_TOKEN);
    assert.equal(response.status, 201, JSON.stringify(response.data));
    assets.push(response.data.assetId);
    return response.data as { assetId: string; token: string };
  }
  async function task(assetId: string, label: string) {
    const response = await call("/tasks", "POST", { title: prefix + label, assetId, template: "FILE_PERMISSION", parameters: { path: "/fixture/batch-review", mode: "0600" } });
    assert.equal(response.status, 201, JSON.stringify(response.data));
    tasks.push(response.data.id);
    return response.data;
  }
  async function batch(taskIds: string[], stopOnFailure = true) {
    const response = await call("/workflows/batches", "POST", { title: prefix, taskIds, stopOnFailure });
    assert.equal(response.status, 201, JSON.stringify(response.data));
    batches.push(response.data.id);
    return response.data;
  }
  async function approve(id: string) {
    const response = await call(`/tasks/${id}/approve`, "POST", {});
    assert.equal(response.status, 201, JSON.stringify(response.data));
  }
  async function poll(auth: string) {
    const response = await call("/agent/tasks", "GET", undefined, auth);
    assert.equal(response.status, 200, JSON.stringify(response.data));
    return response.data.items as Array<{ id: string; template:string; parameters?:any }>;
  }
  try {
    const login = await call("/auth/login", "POST", { email: process.env.ADMIN_EMAIL || "admin@selfguard.local", password: process.env.ADMIN_PASSWORD });
    assert.equal(login.status, 200, JSON.stringify(login.data));
    token = login.data.token;

    await t.test("concurrent polls across agents cannot overlap a batch, including verification", async () => {
      const agents = [await agent("-serial-a"), await agent("-serial-b")];
      const members = [await task(agents[0].assetId, "-serial-1"), await task(agents[1].assetId, "-serial-2"), await task(agents[0].assetId, "-serial-3"), await task(agents[1].assetId, "-serial-4")];
      await batch(members.map(x => x.id));
      for (const member of members) await approve(member.id);
      const claimed = (await Promise.all(Array.from({ length: 8 }, (_, i) => poll(agents[i % 2].token)))).flat();
      assert.equal(claimed.length, 1, "batch claimed more than one task concurrently");
      const active = members.find(x => x.id === claimed[0].id)!;
      const owner = agents.find(a => a.assetId === active.assetId)!;
      assert.equal((await call(`/agent/tasks/${active.id}/result`, "POST", { success: true, evidence: "fixture change completed" }, owner.token)).status, 201);
      assert.equal((await db.task.findUniqueOrThrow({ where: { id: active.id } })).status, "VERIFYING");
      const during=(await Promise.all(agents.map(a=>poll(a.token)))).flat();assert.equal(during.filter(x=>x.template!=='VERIFY_READ').length,0,'batch advanced before independent verification');assert.equal(during.length,1);
      assert.equal((await call(`/agent/tasks/${during[0].id}/result`,'POST',{success:true,evidence:'independent fixture readback passed',details:{verifiedTaskId:active.id,verificationPassed:'true'}},owner.token)).status,201);
      assert.equal((await db.task.findUniqueOrThrow({where:{id:active.id}})).status,'SUCCEEDED');
      const next = (await Promise.all(agents.map(a => poll(a.token)))).flat();
      assert.equal(next.length, 1, "verified task did not release exactly one next batch member");
      assert.notEqual(next[0].id, active.id);
    });

    await t.test("concurrent batch creation cannot move a task between two accepted batches",async()=>{
      const a=await agent("-group-race"),member=await task(a.assetId,"-group-race");
      const responses=await Promise.all(Array.from({length:8},()=>call("/workflows/batches","POST",{title:prefix+"-race",taskIds:[member.id],stopOnFailure:true})));
      const accepted=responses.filter(response=>response.status===201);
      batches.push(...accepted.map(response=>response.data.id));
      assert.equal(accepted.length,1,"same pending task was accepted into multiple batches");
      assert.ok(responses.every(response=>response.status===201||response.status===409),JSON.stringify(responses));
      assert.equal((await db.task.findUniqueOrThrow({where:{id:member.id}})).batchId,accepted[0].data.id);
    });

    await t.test("failure immediately stops the batch and cancels approved and unapproved remainder", async () => {
      const a = await agent("-failure-a"), b = await agent("-failure-b");
      const first = await task(a.assetId, "-failure-first"), approved = await task(b.assetId, "-failure-approved"), pending = await task(b.assetId, "-failure-pending");
      const group = await batch([first.id, approved.id, pending.id]);
      await approve(first.id); await approve(approved.id);
      assert.deepEqual((await poll(a.token)).map(x => x.id), [first.id]);
      assert.equal((await call(`/agent/tasks/${first.id}/result`, "POST", { success: false, evidence: "fixture precondition failed" }, a.token)).status, 201);
      assert.equal((await db.taskBatch.findUniqueOrThrow({ where: { id: group.id } })).status, "STOPPED", "failure was committed without stopping the batch");
      assert.deepEqual((await db.task.findMany({ where: { id: { in: [approved.id, pending.id] } } })).map(x => x.status), ["CANCELLED", "CANCELLED"]);
      assert.deepEqual(await poll(b.token), []);
    });

    await t.test("unknown timeout stops the batch even if every remaining task is unapproved",async()=>{
      const a=await agent("-unknown-a"),b=await agent("-unknown-b");
      const first=await task(a.assetId,"-unknown-first"),pending=await task(b.assetId,"-unknown-pending");
      const group=await batch([first.id,pending.id]);await approve(first.id);
      assert.deepEqual((await poll(a.token)).map(x=>x.id),[first.id]);
      await db.task.update({where:{id:first.id},data:{claimedAt:new Date(Date.now()-16*60000)}});
      assert.deepEqual(await poll(a.token),[]);
      assert.equal((await db.task.findUniqueOrThrow({where:{id:first.id}})).status,"UNKNOWN");
      assert.equal((await db.taskBatch.findUniqueOrThrow({where:{id:group.id}})).status,"STOPPED");
      assert.equal((await db.task.findUniqueOrThrow({where:{id:pending.id}})).status,"CANCELLED");
    });

    await t.test("failed independent verification stops remaining batch work", async () => {
      const a=await agent("-verification-failure"),first=await task(a.assetId,"-verify-first"),pending=await task(a.assetId,"-verify-pending");
      const group=await batch([first.id,pending.id]);await approve(first.id);
      assert.deepEqual((await poll(a.token)).map(x=>x.id),[first.id]);
      assert.equal((await call(`/agent/tasks/${first.id}/result`,"POST",{success:true,evidence:"fixture applied"},a.token)).status,201);
      assert.equal((await call(`/tasks/${first.id}/verify`,"POST",{resolved:false,evidence:"independent fixture check failed"})).status,201);
      assert.equal((await db.taskBatch.findUniqueOrThrow({where:{id:group.id}})).status,"STOPPED");
      assert.equal((await db.task.findUniqueOrThrow({where:{id:pending.id}})).status,"CANCELLED");
    });

    await t.test("stopOnFailure false permits the next batch member after failure",async()=>{
      const a=await agent("-continue"),first=await task(a.assetId,"-continue-first"),next=await task(a.assetId,"-continue-next");
      const group=await batch([first.id,next.id],false);await approve(first.id);await approve(next.id);
      assert.deepEqual((await poll(a.token)).map(x=>x.id),[first.id]);
      assert.equal((await call(`/agent/tasks/${first.id}/result`,"POST",{success:false,evidence:"fixture failed but continuation enabled"},a.token)).status,201);
      assert.equal((await db.taskBatch.findUniqueOrThrow({where:{id:group.id}})).status,"RUNNING");
      assert.deepEqual((await poll(a.token)).map(x=>x.id),[next.id]);
    });

    await t.test("future and elapsed execution windows cannot be claimed and rescheduling invalidates approval", async () => {
      const a = await agent("-windows");
      const future = await task(a.assetId, "-future"), elapsed = await task(a.assetId, "-elapsed"), ready = await task(a.assetId, "-ready");
      const notBefore = new Date(Date.now() + 3600000).toISOString(), windowEnd = new Date(Date.now() + 7200000).toISOString();
      for (const member of [future, elapsed]) {
        assert.equal((await call(`/workflows/tasks/${member.id}/window`, "POST", { notBefore, windowEnd })).status, 201);
      }
      for (const member of [future, elapsed, ready]) await approve(member.id);
      // Move only the fixture's clock boundary to simulate an already elapsed window.
      await db.task.update({ where: { id: elapsed.id }, data: { notBefore: new Date(Date.now() - 7200000), windowEnd: new Date(Date.now() - 3600000) } });
      assert.deepEqual((await poll(a.token)).map(x => x.id), [ready.id]);
      const changed = await call(`/workflows/tasks/${future.id}/window`, "POST", { notBefore, windowEnd });
      assert.equal(changed.status, 201); assert.equal(changed.data.status, "PENDING"); assert.equal(changed.data.approvedBy, null);
      assert.deepEqual(await poll(a.token), []);
    });

    await t.test("archived agent cannot fetch policy, heartbeat, claim or submit results", async () => {
      const a = await agent("-archived");
      const member = await task(a.assetId, "-archived"); await approve(member.id);
      assert.equal((await call(`/workflows/assets/${a.assetId}/archive`, "POST", { archived: true })).status, 201);
      for (const [path, method, body] of [["/agent/policy", "GET", undefined], ["/agent/tasks", "GET", undefined], ["/agent/heartbeat", "POST", { inventory: {}, findings: [] }], [`/agent/tasks/${member.id}/result`, "POST", { success: true, evidence: "forged fixture result" }]] as const) {
        assert.equal((await call(path, method, body, a.token)).status, 401, path);
      }
      assert.equal((await db.task.findUniqueOrThrow({ where: { id: member.id } })).status, "APPROVED");
    });

    await t.test("approval HTTP route denies an unconfigured role and policy helper enforces self-approval", async () => {
      const a = await agent("-approval"), member = await task(a.assetId, "-approval");
      const user = await call("/users", "POST", { email: prefix + "@test.local", name: prefix, password: "Batch-test-password-123!", role: "VIEWER" });
      assert.equal(user.status, 201); users.push(user.data.id);
      const viewerLogin = await call("/auth/login", "POST", { email: user.data.email, password: "Batch-test-password-123!" }); assert.equal(viewerLogin.status, 200);
      assert.equal((await call(`/tasks/${member.id}/approve`, "POST", {}, viewerLogin.data.token)).status, 403);
      assert.equal((await db.task.findUniqueOrThrow({ where: { id: member.id } })).status, "PENDING");
      // Roll back the policy fixture, so no other HTTP request observes a changed organization policy.
      const rollback = new Error("rollback isolated policy fixture");
      await assert.rejects(db.$transaction(async tx => {
        await tx.setting.upsert({ where: { key: "approval-policy" }, create: { key: "approval-policy", value: { approverRoles: ["VIEWER"], allowSelfApproval: false } }, update: { value: { approverRoles: ["VIEWER"], allowSelfApproval: false } } });
        await assertTaskApproval(tx, { requestedBy: login.data.user.email }, user.data.email);
        await assert.rejects(() => assertTaskApproval(tx, { requestedBy: user.data.email }, user.data.email), /自批/);
        await assert.rejects(() => assertTaskApproval(tx, { requestedBy: user.data.email }, login.data.user.email), /权限/);
        throw rollback;
      }), error => error === rollback);
    });
  } finally {
    // Delete only this test's fixtures; leave shared data and settings untouched.
    await db.task.deleteMany({ where: { OR:[{id:{in:tasks}},{assetId:{in:assets}}] } });
    await db.taskBatch.deleteMany({ where: { id: { in: batches } } });
    await db.asset.deleteMany({ where: { id: { in: assets } } });
    await db.session.deleteMany({ where: { userId: { in: users } } });
    await db.user.deleteMany({ where: { id: { in: users } } });
    await db.audit.deleteMany({ where: { OR: [{ resourceId: { in: [...assets, ...tasks, ...batches, ...users] } }, { actor: { startsWith: "agent:", in: assets.map(id => "agent:" + id) } }] } });
    if (token) await call("/auth/logout", "POST", {});
    await db.$disconnect();
  }
});
