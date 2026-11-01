import { test } from "node:test";
import assert from "node:assert/strict";
const base = process.env.TEST_API_URL;
test(
  "real PostgreSQL API: auth, RBAC, enrollment, dedup, incident, approval, claim and verification",
  { skip: !base },
  async () => {
    const suffix = Date.now().toString();
    let token = "";
    async function call(
      path: string,
      method = "GET",
      body?: unknown,
      auth = token,
    ) {
      const r = await fetch(base + path, {
        method,
        headers: {
          "content-type": "application/json",
          ...(auth ? { authorization: `Bearer ${auth}` } : {}),
        },
        body: body === undefined ? undefined : JSON.stringify(body),
      });
      const data = await r.json();
      return { status: r.status, data };
    }
    assert.equal((await call("/assets")).status, 401);
    const login = await call("/auth/login", "POST", {
      email: process.env.ADMIN_EMAIL || "admin@selfguard.local",
      password: process.env.ADMIN_PASSWORD,
    });
    assert.equal(login.status, 200);
    token = login.data.token;
    const viewer = await call("/users", "POST", {
      email: `viewer-${suffix}@test.local`,
      name: "Read only",
      password: "Long-test-password-123!",
      role: "VIEWER",
    });
    assert.equal(viewer.status, 201);
    const vl = await call("/auth/login", "POST", {
      email: viewer.data.email,
      password: "Long-test-password-123!",
    });
    assert.equal(
      (
        await call(
          "/assets",
          "POST",
          { hostname: "no", os: "linux" },
          vl.data.token,
        )
      ).status,
      403,
    );
    const en = await call(
      "/agent/enroll",
      "POST",
      {
        hostname: `test-${suffix}`,
        os: "linux",
        identity: `test-${suffix}`,
        agentVersion: "0.1",
      },
      process.env.ENROLLMENT_TOKEN,
    );
    assert.equal(en.status, 201);
    const agent = en.data;
    const registration = {
      hostname: `retry-${suffix}`,
      os: "linux",
      identity: `retry-${suffix}`,
      credential: "test-client-secret-" + suffix + "-sufficiently-long",
    };
    const first = await call(
      "/agent/enroll",
      "POST",
      registration,
      process.env.ENROLLMENT_TOKEN,
    );
    const replay = await call(
      "/agent/enroll",
      "POST",
      registration,
      process.env.ENROLLMENT_TOKEN,
    );
    assert.equal(replay.status, 201);
    assert.equal(first.data.assetId, replay.data.assetId);
    assert.equal(replay.data.token, registration.credential);
    assert.equal(
      (
        await call(
          "/agent/enroll",
          "POST",
          {
            ...registration,
            credential: "different-client-secret-with-at-least32characters",
          },
          process.env.ENROLLMENT_TOKEN,
        )
      ).status,
      409,
    );
    const heartbeat = {
      inventory: { packages: [] },
      findings: [
        {
          externalId: "permission-1",
          title: "配置文件权限过宽",
          kind: "RISK",
          severity: "HIGH",
          source: "agent",
          evidence: "mode 0666",
        },
      ],
    };
    assert.equal(
      (await call("/agent/heartbeat", "POST", heartbeat, agent.token)).status,
      201,
    );
    assert.equal(
      (await call("/agent/heartbeat", "POST", heartbeat, agent.token)).status,
      201,
    );
    const fs = await call(`/findings?assetId=${agent.assetId}`);
    assert.equal(fs.data.total, 1);
    const finding = fs.data.items[0];
    assert.equal(finding.occurrences, 2);
    assert.equal(
      (await call("/findings/" + finding.id, "PATCH", { status: "CLOSED" }))
        .status,
      400,
    );
    const incident = await call("/incidents", "POST", {
      title: "Investigate",
      severity: "HIGH",
      description: "Test evidence",
      findingIds: [finding.id],
    });
    assert.equal(incident.status, 201);
    assert.equal(incident.data.findingIds[0], finding.id);
    const t = await call("/tasks", "POST", {
      title: "修复配置权限",
      assetId: agent.assetId,
      findingId: finding.id,
      template: "FILE_PERMISSION",
      parameters: { path: "/srv/selfguard-fixture/config", mode: "0600" },
    });
    assert.equal(t.status, 201);
    const preview=(await call('/tasks/'+t.data.id)).data.plan;assert.equal(preview.version,'1');assert.ok(preview.preconditions.length&&preview.restore.length&&preview.verification.length);
    assert.equal(
      (
        await call(`/tasks/${t.data.id}/verify`, "POST", {
          resolved: true,
          evidence: "early",
        })
      ).status,
      409,
    );
    assert.equal(
      (await call(`/tasks/${t.data.id}/approve`, "POST", {})).status,
      201,
    );
    const [a, b] = await Promise.all([
      call("/agent/tasks", "GET", undefined, agent.token),
      call("/agent/tasks", "GET", undefined, agent.token),
    ]);
    assert.equal(a.data.items.length + b.data.items.length, 1);
    assert.equal(
      (
        await call(
          `/agent/tasks/${t.data.id}/result`,
          "POST",
          { success: true, evidence: "chmod succeeded" },
          agent.token,
        )
      ).status,
      201,
    );
    assert.equal((await call(`/tasks/${t.data.id}`)).data.status, "VERIFYING");
    assert.equal(
      (
        await call(
          `/agent/tasks/${t.data.id}/result`,
          "POST",
          { success: true, evidence: "chmod succeeded" },
          agent.token,
        )
      ).status,
      201,
    );
    assert.notEqual(
      (await call(`/findings/${finding.id}`)).data.status,
      "CLOSED",
    );
    assert.equal(
      (
        await call(`/tasks/${t.data.id}/verify`, "POST", {
          resolved: true,
          evidence: "independent stat verified 0600",
        })
      ).status,
      201,
    );
    assert.equal((await call(`/findings/${finding.id}`)).data.status, "CLOSED");
    assert.equal(
      (await call("/tasks/" + t.data.id + "/approve", "POST", {})).status,
      409,
    );
    assert.equal((await call("/audit")).status, 200);
    const upload = await call(`/findings/${finding.id}/attachments`, "POST", {
      name: "evidence.txt",
      contentType: "text/plain",
      data: Buffer.from("fixture evidence").toString("base64"),
    });
    assert.equal(upload.status, 201);
    assert.equal(
      (await call(`/findings/${finding.id}/attachments/${upload.data.id}`)).data
        .data,
      Buffer.from("fixture evidence").toString("base64"),
    );
    assert.equal(
      (
        await call(
          `/findings/${finding.id}/attachments`,
          "POST",
          { name: "x.txt", contentType: "text/plain", data: "dGVzdA==" },
          vl.data.token,
        )
      ).status,
      403,
    );
    assert.equal(
      (
        await call(`/tasks/${t.data.id}/comments`, "POST", {
          body: "Reviewed test evidence",
        })
      ).status,
      201,
    );
    assert.equal(
      (
        await call(
          `/users/${viewer.data.id}/comments`,
          "GET",
          undefined,
          vl.data.token,
        )
      ).status,
      403,
    );
    assert.equal(
      (await call("/operations/health", "GET", undefined, vl.data.token))
        .status,
      403,
    );
    for (const path of [
      "/discoveries",
      "/operations/health",
      "/operations/business-groups",
      "/operations/trends",
      "/operations/exports",
      "/operations/credentials",
      "/operations/notifications",
      "/evaluations",
      "/waf-nodes",
    ])
      assert.equal((await call(path)).status, 200, path);
    const vr = await call("/rules", "POST", {
      name: "test advisory",
      kind: "VULNERABILITY",
      severity: "HIGH",
      config: {
        package: "fixture",
        affectedVersion: "1",
        os: "linux",
        advisory: "local test",
      },
    });
    assert.equal(vr.status, 201);
    assert.equal(
      (
        await call(`/rules/${vr.data.id}/run`, "POST", {
          assetId: agent.assetId,
        })
      ).status,
      201,
    );
    assert.equal(
      (await call(`/rules/${vr.data.id}`, "PATCH", { name: "new name" }))
        .status,
      200,
    );
    const versions = await call(`/rules/${vr.data.id}/versions`);
    assert.equal(versions.data.items.length, 2);
    const restored = await call(`/rules/${vr.data.id}/restore`, "POST", {
      version: 1,
    });
    assert.equal(restored.status, 201);
    assert.equal(restored.data.name, "test advisory");
    assert.equal(restored.data.version, 3);
    const cfgTask = await call("/tasks", "POST", {
      title: "Config fixture",
      assetId: agent.assetId,
      template: "CONFIG_VALUE",
      parameters: {
        path: "/srv/fixture/config",
        key: "FEATURE",
        expectedValue: "yes",
        value: "no",
      },
    });
    assert.equal(cfgTask.status, 201);
    const hidden = await call(
      "/tasks/" + cfgTask.data.id,
      "GET",
      undefined,
      vl.data.token,
    );
    assert.equal(hidden.data.parameters.value, "[已隐藏]");
    assert.equal((await call(`/tasks/${cfgTask.data.id}/approve`,'POST',{})).status,201);
    await call('/agent/tasks','GET',undefined,agent.token);
    assert.equal((await call(`/agent/tasks/${cfgTask.data.id}/result`,'POST',{success:false,evidence:'service job outcome unknown',details:{resultUnknown:'true'}},agent.token)).status,201);
    assert.equal((await call('/tasks/'+cfgTask.data.id)).data.status,'UNKNOWN');
    assert.equal(
      (await call(`/operations/assets/${agent.assetId}/revoke`, "POST", {}))
        .status,
      201,
    );
    assert.equal(
      (await call("/agent/policy", "GET", undefined, agent.token)).status,
      401,
    );
    assert.equal((await call("/auth/logout", "POST", {})).status, 201);
    assert.equal((await call("/assets")).status, 401);
  },
);
test('concurrent HTTP logins enforce shared reservations on a dedicated test source',{skip:!base},async()=>{
 const {request}=await import('node:http');const {Db}=await import('../src/db');const {hashToken}=await import('../src/security');const db=new Db();const key='auth-rate:'+hashToken('127.0.0.2');
 try{await db.setting.deleteMany({where:{key}});const responses=await Promise.all(Array.from({length:14},()=>new Promise<number>((resolve,reject)=>{const u=new URL(base+'/auth/login');const r=request(u,{method:'POST',localAddress:'127.0.0.2',headers:{'content-type':'application/json'}},res=>{res.resume();res.on('end',()=>resolve(res.statusCode||0))});r.on('error',reject);r.end(JSON.stringify({email:'missing@example.invalid',password:'wrong'}))})));assert.equal(responses.filter(x=>x===403).length,4);
 }finally{await db.setting.deleteMany({where:{key}});await db.$disconnect()}
});
