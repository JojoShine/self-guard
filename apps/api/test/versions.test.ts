import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { compareDebianVersions, matchesOsvRange } from "../src/versions";

const fixtures: Array<[string,string,-1|0|1]> = [
 ["1","1-0",0],["0:1.0","1.0",0],["0001:1","1:1",0],
 ["1.0-1","1.0-2",-1],["1.0-9","1.0-10",-1],["1.0-01","1.0-1",0],
 ["1:1.0-1","2.0-99",1],["2:0.1","1:9999",1],
 ["1.0~rc1","1.0",-1],["1.0~~","1.0~",-1],["1.0~~a","1.0~",-1],
 ["1.0-1~bpo12+1","1.0-1",-1],["1.0-1+deb12u1","1.0-1",1],
 ["1.0-1ubuntu9","1.0-1ubuntu10",-1],["1.0-1ubuntu1.2","1.0-1ubuntu1.10",-1],
 ["2.3+really2.2-1","2.3-3",1],["1.0a","1.0+",-1],["1.0+","1.0.",-1],
 ["1.0A","1.0a",-1],["1.000","1.0",0],["1.0","1.0a",-1],
 ["1.0-0~","1.0",-1],["1.0-a","1.0-+",-1],["1.0+0","1.0+",0],
 ["1.2-3-4","1.2-3-5",-1],
 ["1.9999999999999999999999999","1.10000000000000000000000000",-1],
 ["3.0.0-1~deb12u2","3.0.0-1~deb12u10",-1],
];

test("Debian epoch/upstream/revision and modified ASCII/numeric ordering", () => {
 for(const [a,b,want] of fixtures){
  assert.equal(compareDebianVersions(a,b),want,`${a} vs ${b}`);
  assert.equal(compareDebianVersions(b,a),want===0?0:-want,`${b} vs ${a}`);
 }
 assert.equal(compareDebianVersions("9999999999999999999999999:1","10000000000000000000000000:0"),-1);
});
test("Debian rejects malformed or unsupported version syntax",()=>{
 for(const bad of ["","v1","1:",":1","1:2:3","-1","1-","1_0","1^2","1 2"," 1","1\n","1/2","1-*","1".repeat(4097)])
  assert.throws(()=>compareDebianVersions(bad,"1"),bad);
});
test("OSV fixed exclusive, introduced inclusive, gaps and unsorted events",()=>{
 const events=[{fixed:"2.1-1"},{introduced:"1.0-1"},{fixed:"1.2-3"},{introduced:"2.0"}];
 for(const [v,want] of [["0.9",false],["1.0-1",true],["1.2-3~bpo12+1",true],["1.2-3",false],["1.9",false],["2.0",true],["2.1-1",false]] as const)
  assert.equal(matchesOsvRange(v,events),want,v);
});
test("OSV introduced zero sentinel and inclusive last affected",()=>{
 assert.equal(matchesOsvRange("0~pre",[{introduced:"0"}]),true);
 assert.equal(matchesOsvRange("1.2-3",[{introduced:"0"},{last_affected:"1.2-3"}]),true);
 assert.equal(matchesOsvRange("1.2-3+deb12u1",[{introduced:"0"},{last_affected:"1.2-3"}]),false);
 assert.equal(matchesOsvRange("1:0",[{introduced:"0"},{fixed:"1:0"}]),false);
});
test("OSV limit is a global exclusive bound and multiple limits combine by OR",()=>{
 const events=[{introduced:"1"},{limit:"2"},{limit:"3"}];
 assert.equal(matchesOsvRange("2.5",events),true);
 assert.equal(matchesOsvRange("3",events),false);
 assert.equal(matchesOsvRange("100",[...events,{limit:"*"}]),true);
 assert.equal(matchesOsvRange("0.5",events),false);
});
test("OSV malformed or unsupported input throws rather than reporting unaffected",()=>{
 const malformed:any[]=[[],[{}],[{fixed:"1"}],[{introduced:"0",fixed:"1"}],[{introduced:"0"},{last_affected:"1"},{fixed:"2"}],[{introduced:"0"},{limit:"1.*"}],[{introduced:"0"},{fixed:"bad"}],[{introduced:"1"},{fixed:"1-0"}],[{introduced:"0"},{unknown:"2"}],[{introduced:1}],null];
 for(const events of malformed)assert.throws(()=>matchesOsvRange("1",events),JSON.stringify(events));
});
test("Debian fixtures agree with actual dpkg --compare-versions",t=>{
 const probe=spawnSync("dpkg",["--version"],{encoding:"utf8"});
 if(probe.error){t.skip("dpkg unavailable; run this test in the bookworm development container");return;}
 assert.equal(probe.status,0,probe.stderr);
 for(const [a,b,want] of fixtures){
  const result=spawnSync("dpkg",["--compare-versions",a,want===-1?"lt":want===1?"gt":"eq",b],{encoding:"utf8"});
  assert.equal(result.status,0,`${a} vs ${b}: ${result.stderr}`);
 }
});
