import { test } from "node:test";
import assert from "node:assert/strict";
import { evaluateVulnerability } from "../src/evaluation";
test("missing package inventory is unknown not clean", () =>
  assert.equal(
    evaluateVulnerability({ os: "linux" }, { os: "linux", inventory: {} })
      .status,
    "UNKNOWN",
  ));
test("exact matching never compares package versions lexicographically", () => {
  const config = {
    os: "linux",
    package: "demo",
    affectedVersion: "1.10-ubuntu1",
    advisory: "test advisory",
  };
  assert.equal(
    evaluateVulnerability(config, {
      os: "linux",
      inventory: { packages: [{ name: "demo", version: "1.10-ubuntu1" }] },
    }).matched,
    true,
  );
  assert.equal(
    evaluateVulnerability(config, {
      os: "linux",
      inventory: { packages: [{ name: "demo", version: "1.10-ubuntu2" }] },
    }).matched,
    false,
  );
  assert.equal(
    evaluateVulnerability(config, {
      os: "windows",
      inventory: { packages: [] },
    }).status,
    "NOT_APPLICABLE",
  );
});
test('incomplete inventory cannot establish absence of a vulnerability',()=>{
 const c={os:'linux',package:'fixture',affectedVersion:'1',advisory:'test'};
 assert.equal(evaluateVulnerability(c,{os:'linux',inventory:{packages:[],packageCollection:{complete:false,reason:'limited'}}}).status,'UNKNOWN');
 assert.equal(evaluateVulnerability(c,{os:'linux',inventory:{packages:[{name:'fixture',version:'1'}],packageCollection:{complete:false}}}).matched,true);
});
test('OSV Debian ranges require matching distro release and respect fixed boundary',()=>{
 const config={os:'linux',ecosystem:'Debian:12',package:'fixture',ranges:[{type:'ECOSYSTEM',events:[{introduced:'0'},{fixed:'1.2-3'}]}],advisory:'fixture'};
 const inventory={distribution:{id:'debian',versionId:'12'},packages:[{name:'fixture',version:'1.2-2',origin:'fixture',sourceVersion:'1.2-2'}]};
 assert.equal(evaluateVulnerability(config,{os:'linux',inventory}).matched,true);
 assert.equal(evaluateVulnerability(config,{os:'linux',inventory:{...inventory,packages:[{name:'fixture',version:'1.2-3',origin:'fixture',sourceVersion:'1.2-3'}]}}).matched,false);
 assert.equal(evaluateVulnerability(config,{os:'linux',inventory:{...inventory,distribution:{id:'ubuntu',versionId:'22.04'}}}).status,'NOT_APPLICABLE');
});

test('source-based legacy rules use actual source version and report missing metadata as unknown',()=>{const config={os:'linux',ecosystem:'Debian:12',package:'openssl',ranges:[{type:'ECOSYSTEM',events:[{introduced:'0'},{fixed:'3.0.10-1'}]}],advisory:'source-version'};const inventory={distribution:{id:'debian',versionId:'12'},packages:[{name:'libssl3',version:'3.0.9-1+b9',origin:'openssl',sourceVersion:'3.0.9-1'}]};const hit=evaluateVulnerability(config,{os:'linux',inventory});assert.equal(hit.matched,true);assert.equal(JSON.parse(hit.evidence).observations[0].sourceVersion,'3.0.9-1');assert.equal(evaluateVulnerability(config,{os:'linux',inventory:{...inventory,packages:[{name:'openssl',version:'3.0.9-1'}]}}).status,'UNKNOWN');});
