import { test } from "node:test";
import assert from "node:assert/strict";
import {
  findingTransition,
  taskTransition,
  validateTaskParameters,
  redactEvent,
} from "../src/domain";
test("risk cannot close directly or be accepted without rationale and expiry", () => {
  assert.throws(() => findingTransition("RISK", "OPEN", "CLOSED", {}));
  assert.throws(() =>
    findingTransition("RISK", "OPEN", "ACCEPTED", { reason: "temporary" }),
  );
  assert.equal(
    findingTransition("RISK", "OPEN", "ACCEPTED", {
      reason: "planned patch",
      expiresAt: new Date(Date.now() + 86400000).toISOString(),
    }),
    "ACCEPTED",
  );
});
test("alerts and risks have different terminal transitions", () => {
  assert.equal(
    findingTransition("ALERT", "OPEN", "RESOLVED", {
      reason: "blocked and investigated",
    }),
    "RESOLVED",
  );
  assert.throws(() => findingTransition("ALERT", "OPEN", "ACCEPTED", {}));
});
test("task only follows approval execution and verification", () => {
  assert.equal(taskTransition("PENDING", "approve"), "APPROVED");
  assert.equal(taskTransition("RUNNING", "success"), "VERIFYING");
  assert.throws(() => taskTransition("PENDING", "success"));
  assert.throws(() => taskTransition("APPROVED", "verify"));
  assert.equal(taskTransition("VERIFYING", "verify"), "SUCCEEDED");
});
test("repair template rejects root paths, relative paths and insecure modes", () => {
  assert.throws(() =>
    validateTaskParameters({ path: "/etc/passwd", mode: "0777" }),
  );
  assert.throws(() => validateTaskParameters({ path: "../x", mode: "0600" }));
  assert.throws(() => validateTaskParameters({ path: "/", mode: "0600" }));
  assert.deepEqual(
    validateTaskParameters({ path: "/srv/test/config", mode: "0600" }),
    { path: "/srv/test/config", mode: "0600" },
  );
});
test("WAF event removes queries credentials and limits path size", () => {
  const e = redactEvent({
    path: "/login?token=secret",
    method: "GET",
    remoteIp: "127.0.0.1",
    action: "BLOCK",
    ruleId: "sqli",
  });
  assert.equal(e.path, "/login");
  assert.ok(!JSON.stringify(e).includes("secret"));
});
test("configuration repair is literal and precondition-bound", async () => {
  const { validateConfigParameters } = await import("../src/domain");
  assert.deepEqual(
    validateConfigParameters({
      path: "/srv/config",
      key: "SETTING",
      expectedValue: "old",
      value: "new",
    }),
    { path: "/srv/config", key: "SETTING", expectedValue: "old", value: "new" },
  );
  assert.throws(() =>
    validateConfigParameters({
      path: "/srv/config",
      key: "SETTING",
      expectedValue: "old",
      value: "new\nOTHER=x",
    }),
  );
  assert.throws(() =>
    validateConfigParameters({
      path: "/srv/config",
      key: "SETTING",
      value: "new",
    }),
  );
});
test('service repair requires explicit unit and restorable expected state',async()=>{
 const {validateServiceParameters}=await import('../src/domain');
 assert.deepEqual(validateServiceParameters({service:'auditd.service',expectedState:'inactive',state:'active'}),{service:'auditd.service',expectedState:'inactive',state:'active'});
 assert.throws(()=>validateServiceParameters({service:'x;touch /tmp/x',expectedState:'inactive',state:'active'}));
 assert.throws(()=>validateServiceParameters({service:'x.service',expectedState:'failed',state:'active'}));
});
