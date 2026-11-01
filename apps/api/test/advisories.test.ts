import { test } from "node:test";
import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { PassThrough } from "node:stream";
import { advisoryUrl, publicAddress, normalizeOsv, fetchAdvisory, syncAdvisory } from "../src/advisories";
import { Db } from "../src/db";

const fixture = {
  id: "TEST-2026-001", database_specific: { severity: "HIGH" },
  affected: [
    { package: { ecosystem: "Debian:12", name: "fixture-package" }, versions: ["1.0-1", "1.0-1", "1.0-2"], ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "0" }, { fixed: "1.0-3" }] }] },
    { package: { ecosystem: "npm", name: "fixture-package" }, versions: ["1.0"] },
  ],
};
test("advisory URLs and IP validation refuse SSRF, redirects targets and nonpublic networks", () => {
  assert.equal(advisoryUrl("https://api.osv.dev/v1/vulns/CVE-2026-0001").hostname, "api.osv.dev");
  for (const url of ["http://api.osv.dev/v1/vulns/X", "https://api.osv.dev@127.0.0.1/v1/vulns/X", "https://api.osv.dev:444/v1/vulns/X", "https://api.osv.dev/other", "https://example.com/v1/vulns/X", "https://api.osv.dev/v1/vulns/X?target=localhost", "https://api.osv.dev/v1/vulns/X#fragment"]) assert.throws(() => advisoryUrl(url));
  assert.equal(advisoryUrl("https://feed.example.org/osv/X", "feed.example.org").hostname, "feed.example.org");
  for (const ip of ["127.0.0.1", "10.0.0.1", "169.254.169.254", "172.16.0.1", "192.168.0.1", "100.64.0.1", "224.0.0.1", "::1", "::ffff:127.0.0.1", "::ffff:7f00:1", "fc00::1", "fe80::1", "2001:db8::1", "2002:7f00:1::"]) assert.equal(publicAddress(ip), false, ip);
  assert.equal(publicAddress("8.8.8.8"), true);
  assert.equal(publicAddress("2606:4700:4700::1111"), true);
});
test("OSV normalization preserves supported exact versions and ranges with source trace", () => {
  const result = normalizeOsv(fixture, "https://api.osv.dev/v1/vulns/TEST-2026-001", "source-id");
  assert.equal(result.rules.length, 3);
  assert.equal(result.skippedRanges, 0);
  assert.deepEqual(result.skippedEcosystems, ["npm"]);
  assert.equal(result.rules[0].config.affectedVersion, "1.0-1");
  assert.equal(result.rules[0].config.ecosystem, "Debian:12");
  assert.equal(result.rules[0].config.advisory, "https://api.osv.dev/v1/vulns/TEST-2026-001");
  assert.equal(result.rules[0].severity, "HIGH");
  assert.equal(result.rules[0].config.fixedVersion, undefined);
  assert.equal(normalizeOsv({ ...fixture, withdrawn: "2026-01-01T00:00:00Z" }, "https://api.osv.dev/v1/vulns/TEST-2026-001", "source-id").rules.length, 0);
});
function transport(statusCode: number, body: string) {
  return (_url: any, _options: any, callback: any) => {
    const request: any = new EventEmitter();
    request.end = () => queueMicrotask(() => {
      const response = new PassThrough() as any;
      response.statusCode = statusCode;
      callback(response);
      response.end(body);
    });
    request.destroy = () => request;
    return request;
  };
}
test("advisory downloader bounds payloads and rejects redirects, HTTP errors and malformed JSON", async () => {
  const url = "https://api.osv.dev/v1/vulns/X";
  assert.deepEqual(await fetchAdvisory(url, { request: transport(200, '{"id":"X"}') }), { id: "X" });
  await assert.rejects(() => fetchAdvisory(url, { request: transport(302, "") }), /重定向/);
  await assert.rejects(() => fetchAdvisory(url, { request: transport(500, "error") }), /500/);
  await assert.rejects(() => fetchAdvisory(url, { request: transport(200, "not json") }), /JSON/);
  await assert.rejects(() => fetchAdvisory(url, { request: transport(200, "x".repeat(2 * 1024 * 1024 + 1)) }), /上限/);
});
test("real isolated database source sync persists retry state and versions without duplicate rules", { skip: !process.env.GOVERNANCE_TEST_ISOLATED }, async () => {
  assert.match(process.env.DATABASE_URL || "", /[?&]schema=governance_test_[a-zA-Z0-9_]+(?:&|$)/);
  const db = new Db();
  try {
    const source = await db.advisorySource.create({ data: { name: "Advisory test", url: "https://api.osv.dev/v1/vulns/TEST-2026-001", format: "OSV", enabled: true, status: "IDLE" } });
    const failed = await syncAdvisory(db, source.id, "test@local", async () => { throw new Error("timeout"); });
    assert.equal(failed.source.status, "FAILED");
    const first = await syncAdvisory(db, source.id, "test@local", async () => fixture);
    assert.equal(first.summary.imported, 3);
    assert.equal(first.source.status, "PARTIAL");
    const second = await syncAdvisory(db, source.id, "test@local", async () => fixture);
    assert.equal(second.summary.imported, 3);
    assert.equal(await db.rule.count(), 3);
    assert.equal(await db.revision.count({ where: { resource: "rules" } }), 3, "unchanged sync must not fabricate new revisions");
    const malformed = await syncAdvisory(db, source.id, "test@local", async () => ({ ...fixture, affected: [{ package: { ecosystem: "Debian:12", name: "fixture-package" }, ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "0", fixed: "2.0" }] }] }] }));
    assert.equal(malformed.source.status, "FAILED");
    assert.match(malformed.source.error!, /OSV 范围无效/);
    assert.equal(malformed.source.lastSyncAt!.getTime(), second.source.lastSyncAt!.getTime(), "failed sync preserves last successful snapshot time");
    assert.equal(await db.rule.count({ where: { enabled: true } }), 3, "malformed replacement must retain previous successful rules");
    assert.equal(await db.revision.count({ where: { resource: "rules" } }), 3, "failed synchronization must not partially change rule revisions");
    const withdrawn = await syncAdvisory(db, source.id, "test@local", async () => ({ ...fixture, withdrawn: "2026-01-01T00:00:00Z" }));
    assert.equal(withdrawn.summary.withdrawn, true);
    assert.equal(await db.rule.count({ where: { enabled: true } }), 0);
  } finally { await db.$disconnect(); }
});
test("advisory socket lookup rejects mixed private DNS answers and pins validated public records", async () => {
  const url = "https://api.osv.dev/v1/vulns/X";
  let pinned: any;
  const request = (_url: any, options: any, callback: any) => {
    const req: any = new EventEmitter();
    req.destroy = () => req;
    req.end = () => queueMicrotask(() => options.lookup("api.osv.dev", { all: true }, (error: Error, records: any) => {
      if (error) return req.emit("error", error);
      pinned = records;
      const response = new PassThrough() as any; response.statusCode = 200;
      callback(response); response.end('{"id":"X"}');
    }));
    return req;
  };
  const mixedLookup: any = (_host: string, _options: any, callback: any) => callback(null, [{ address: "8.8.8.8", family: 4 }, { address: "127.0.0.1", family: 4 }]);
  await assert.rejects(() => fetchAdvisory(url, { request, lookup: mixedLookup }), /非公开/);
  const records = [{ address: "8.8.8.8", family: 4 }];
  const publicLookup: any = (_host: string, _options: any, callback: any) => callback(null, records);
  await fetchAdvisory(url, { request, lookup: publicLookup });
  assert.deepEqual(pinned, records);
});
test("advisory request deadline aborts even when no response arrives", async context => {
  context.mock.timers.enable({ apis: ["setTimeout"] });
  let destroyed = false;
  const request: any = () => {
    const req: any = new EventEmitter(); req.end = () => {};
    req.destroy = () => { destroyed = true; return req; };
    return req;
  };
  const pending = fetchAdvisory("https://api.osv.dev/v1/vulns/X", { request });
  const rejected = assert.rejects(pending, /超时/);
  context.mock.timers.tick(10001);
  await rejected;
  assert.equal(destroyed, true);
});

test("OSV Debian and Ubuntu ranges are preserved while Alpine and unsupported range kinds remain explicit gaps", () => {
  const result = normalizeOsv({ id: "TEST-RANGE", affected: [
    { package: { ecosystem: "Debian:12", name: "debian-package" }, ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "0" }, { fixed: "1:2.0-3" }] }] },
    { package: { ecosystem: "Ubuntu:22.04", name: "ubuntu-package" }, ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "1.0" }, { last_affected: "1.2-0ubuntu1" }] }, { type: "SEMVER", events: [{ introduced: "0" }, { fixed: "2.0.0" }] }] },
    { package: { ecosystem: "Alpine:v3.20", name: "alpine-package" }, versions: ["1.0-r0"], ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "0" }, { fixed: "1.0-r1" }] }] },
  ] }, "https://api.osv.dev/v1/vulns/TEST-RANGE", "source-id");
  assert.equal(result.rules.length, 3);
  assert.equal(result.skippedRanges, 2);
  assert.equal(result.skippedEntries, 0);
  assert.equal(result.rangeRules, 2);
  const rule = result.rules.find(r => r.config.package === "debian-package")!;
  assert.equal(rule.config.affectedVersion, undefined);
  assert.deepEqual(rule.config.ranges, [{ type: "ECOSYSTEM", events: [{ introduced: "0" }, { fixed: "1:2.0-3" }] }]);
  assert.throws(() => normalizeOsv({ id: "INVALID", affected: [{ package: { ecosystem: "Debian:12", name: "pkg" }, ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "0" }, { fixed: "1.0" }, { last_affected: "2.0" }] }] }] }, "https://api.osv.dev/v1/vulns/INVALID", "source-id"));
});
