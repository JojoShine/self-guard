import { test } from "node:test";
import assert from "node:assert/strict";
import { attachmentData } from "../src/attachments";
test("attachment upload enforces name, canonical base64 and bounded size", () => {
  const base = {
    name: "evidence.txt",
    contentType: "text/plain",
    data: Buffer.from("evidence").toString("base64"),
  };
  assert.equal(attachmentData(base).size, 8);
  assert.throws(() => attachmentData({ ...base, name: "../test" }));
  assert.throws(() => attachmentData({ ...base, data: "AAAAA" }));
  assert.throws(() =>
    attachmentData({ ...base, data: Buffer.alloc(1048577).toString("base64") }),
  );
  assert.throws(() => attachmentData({ ...base, contentType: "text/html" }));
});
