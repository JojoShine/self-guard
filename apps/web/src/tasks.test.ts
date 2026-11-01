import { describe, it, expect } from "vitest";
import { taskParameters } from "./tasks";
describe("controlled task parameters", () => {
  it("keeps file permission tasks free of stale configuration fields", () => {
    expect(
      taskParameters({
        template: "FILE_PERMISSION",
        path: "/tmp/test",
        permission: "0640",
        configKey: "OLD",
        value: "stale",
      }),
    ).toEqual({ path: "/tmp/test", mode: "0640" });
  });
  it("preserves literal expected and desired config values without treating them as commands", () => {
    expect(
      taskParameters({
        template: "CONFIG_VALUE",
        path: "/tmp/app.conf",
        configKey: "MODE",
        expectedValue: "old value",
        value: "new=value",
        permission: "0600",
      }),
    ).toEqual({
      path: "/tmp/app.conf",
      key: "MODE",
      expectedValue: "old value",
      value: "new=value",
    });
  });
});
it('serializes service state without stale file parameters',()=>{
 expect(taskParameters({template:'SERVICE_STATE',service:'auditd.service',expectedState:'inactive',serviceState:'active',path:'/unrelated',permission:'0600'})).toEqual({service:'auditd.service',expectedState:'inactive',state:'active'});
});
