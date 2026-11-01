import { test } from "node:test";
import assert from "node:assert/strict";
import { siteInput } from "../src/validation";
import { Platform } from "../src/platform";
test("management rejects sites the WAF cannot load", () => {
  assert.equal(
    siteInput.safeParse({
      name: "x",
      hostname: "x:443",
      upstream: "http://upstream",
    }).success,
    false,
  );
  assert.equal(
    siteInput.safeParse({
      name: "x",
      hostname: "x.local",
      upstream: "http://upstream/#secret",
    }).success,
    false,
  );
  const p = new Platform({} as any);
  assert.throws(() => p.validateSiteConfig({ maxBodyBytes: 9 * 1024 * 1024 }));
  assert.throws(() => p.validateSiteConfig({ denyCidrs: ["not-a-cidr"] }));
  assert.doesNotThrow(() =>
    p.validateSiteConfig({ denyCidrs: ["10.0.0.0/8", "::1/128"] }),
  );
});
test('partial edits do not implicitly re-enable disabled policies',async()=>{
 const {ruleInput,assetInput,siteInput}=await import('../src/validation');
 assert.deepEqual(ruleInput.partial().parse({name:'rename'}),{name:'rename'});
 assert.deepEqual(siteInput.partial().parse({name:'rename'}),{name:'rename'});
 assert.deepEqual(assetInput.partial().parse({owner:'new owner'}),{owner:'new owner'});
});
