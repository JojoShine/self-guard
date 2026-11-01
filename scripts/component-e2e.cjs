const fs = require("fs");
const path = require("path");
const assert = require("assert/strict");
const { execFileSync } = require("child_process");
const root = process.cwd();
const env = Object.fromEntries(
  fs
    .readFileSync(".env", "utf8")
    .trim()
    .split("\n")
    .map((l) => {
      const i = l.indexOf("=");
      return [l.slice(0, i), l.slice(i + 1)];
    }),
);
const base = "http://127.0.0.1:4010/api";
let token = "";
function wafRequest(path) {
  return new Promise((resolve, reject) => {
    const req = require("http").request(
      {
        hostname: "127.0.0.1",
        port: 5181,
        path,
        headers: { Host: "fixture.local" },
        timeout: 5000,
      },
      (res) => {
        res.resume();
        res.on("end", () => resolve({ status: res.statusCode }));
      },
    );
    req.on("error", reject);
    req.on("timeout", () => req.destroy(Error("timeout")));
    req.end();
  });
}
function docker(...args) {
  return execFileSync("docker", args, {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  }).trim();
}
async function api(p, body, method) {
  const r = await fetch(base + p, {
    method: method || (body ? "POST" : "GET"),
    headers: {
      "content-type": "application/json",
      authorization: "Bearer " + token,
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  const data = await r.json();
  if (!r.ok) throw Error(p + ": " + r.status + " " + JSON.stringify(data));
  return data;
}
const delay = (ms) => new Promise((r) => setTimeout(r, ms));
async function until(fn, ms = 65000) {
  const end = Date.now() + ms;
  let err;
  while (Date.now() < end) {
    try {
      const r = await fn();
      if (r) return r;
    } catch (e) {
      err = e;
    }
    await delay(1000);
  }
  throw err || Error("Timed out");
}
(async () => {
  const names = [
    "selfguard-test-agent",
    "selfguard-test-waf",
    "selfguard-test-upstream",
  ];
  for (const n of names)
    try {
      docker("rm", "-f", n);
    } catch {}
  const login = await api("/auth/login", {
    email: env.ADMIN_EMAIL,
    password: env.ADMIN_PASSWORD,
  });
  token = login.token;
  const fixture = path.join(root, ".artifacts/fixture-" + Date.now());
  fs.mkdirSync(fixture, { recursive: true });
  fs.writeFileSync(path.join(fixture, "config"), "fixture only\n");
  fs.chmodSync(path.join(fixture, "config"), 0o666);
  const state = path.join(root, ".artifacts/agent-state-" + Date.now());
  fs.mkdirSync(state, { recursive: true });
  await api("/rules", {
    name: "E2E fixture permissions",
    kind: "BASELINE",
    severity: "HIGH",
    enabled: true,
    config: { path: "/fixture/config", mode: "0600" },
  });
  const agentConfig = { Checks: [{ Path: "/fixture/config", Mode: "0600" }] };
  fs.writeFileSync(
    path.join(fixture, "agent.json"),
    JSON.stringify(agentConfig),
  );
  docker(
    "run",
    "-d",
    "--name",
    names[0],
    "--network",
    "selfguard-dev_default",
    "-e",
    "AGENT_SERVER=http://api:4000",
    "-e",
    "AGENT_DEVELOPMENT=true",
    "-e",
    "AGENT_ENROLLMENT_TOKEN=" + env.ENROLLMENT_TOKEN,
    "-e",
    "AGENT_STATE_DIR=/state",
    "-e",
    "AGENT_ALLOWED_ROOT=/fixture",
    "-e",
    "AGENT_CONFIG=/fixture/agent.json",
    "-v",
    path.join(root, ".artifacts/bin/agent") + ":/agent:ro",
    "-v",
    fixture + ":/fixture",
    "-v",
    state + ":/state",
    "node:22-bookworm-slim",
    "/agent",
  );
  const identity = await until(() => {
    const p = path.join(state, "identity.json");
    if (!fs.existsSync(p)) return;
    const j = JSON.parse(fs.readFileSync(p));
    return j.assetId ? j : null;
  });
  console.log("Agent enrolled; awaiting fixture observation.");
  fs.chmodSync(path.join(fixture, "config"), 0o666);
  const finding = await until(async () => {
    const f = await api("/findings?assetId=" + identity.assetId);
    return f.items.find((x) => x.kind === "RISK");
  });
  const task = await api("/tasks", {
    title: "E2E fixture chmod",
    assetId: identity.assetId,
    findingId: finding.id,
    template: "FILE_PERMISSION",
    parameters: { path: "/fixture/config", mode: "0600" },
  });
  await api("/tasks/" + task.id + "/approve", {});
  await until(async () => {
    const t = await api("/tasks/" + task.id);
    if (t.status === "FAILED")
      throw Error("Agent failed: " + JSON.stringify(t.result));
    return ["VERIFYING","SUCCEEDED"].includes(t.status);
  });
  assert.equal(fs.statSync(path.join(fixture, "config")).mode & 0o777, 0o600);
  await until(async()=> (await api('/tasks/'+task.id)).status==='SUCCEEDED');
  assert.equal((await api('/tasks/'+task.id)).verification.actor,'independent-agent-read');
  assert.equal((await api("/findings/" + finding.id)).status, "CLOSED");
  console.log(
    "Agent real E2E passed: enrollment → baseline → approval → actual chmod → independent verification.",
  );
  fs.writeFileSync(path.join(fixture, "feature.env"), "FEATURE=on\n");
  const configTask = await api("/tasks", {
    title: "E2E literal config change",
    assetId: identity.assetId,
    template: "CONFIG_VALUE",
    parameters: {
      path: "/fixture/feature.env",
      key: "FEATURE",
      expectedValue: "on",
      value: "off",
    },
  });
  await api("/tasks/" + configTask.id + "/approve", {});
  await until(async () => {
    const t = await api("/tasks/" + configTask.id);
    if (t.status === "FAILED")
      throw Error("Config failed: " + JSON.stringify(t.result));
    return ["VERIFYING","SUCCEEDED"].includes(t.status);
  });
  assert.equal(
    fs.readFileSync(path.join(fixture, "feature.env"), "utf8"),
    "FEATURE=off\n",
  );
  await until(async()=> (await api('/tasks/'+configTask.id)).status==='SUCCEEDED');
  assert.equal((await api('/tasks/'+configTask.id)).verification.actor,'independent-agent-read');
  const rollback=await api('/repair/'+configTask.id+'/rollback',{});
  await api('/tasks/'+rollback.id+'/approve',{});
  await until(async()=> (await api('/tasks/'+rollback.id)).status==='SUCCEEDED');
  assert.equal(fs.readFileSync(path.join(fixture,'feature.env'),'utf8'),'FEATURE=on\n');
  assert.equal((await api('/tasks/'+configTask.id)).status,'ROLLED_BACK');
  console.log('CONFIG_VALUE real E2E passed: approved edit → independent fresh readback → approved rollback → verified original state.');
  docker(
    "run",
    "-d",
    "--name",
    names[2],
    "--network",
    "selfguard-dev_default",
    "node:22-bookworm-slim",
    "node",
    "-e",
    "require('http').createServer((q,s)=>s.end('fixture upstream')).listen(8090)",
  );
  const existing = await api("/sites?q=fixture.local");
  const site =
    existing.items[0] ||
    (await api("/sites", {
      name: "E2E test upstream",
      hostname: "fixture.local",
      upstream: "http://selfguard-test-upstream:8090",
      mode: "BLOCK",
      enabled: true,
      config: { ratePerMinute: 100 },
    }));
  const config = path.join(root, ".artifacts/waf-config.json");
  fs.writeFileSync(config, JSON.stringify({ sites: [site] }));
  docker(
    "run",
    "-d",
    "--name",
    names[1],
    "--network",
    "selfguard-dev_default",
    "-e",
    "WAF_TOKEN=" + env.WAF_TOKEN,
    "-e",
    "WAF_API_URL=http://api:4000",
    "-e",
    "WAF_DEVELOPMENT=true",
    "-e",
    "WAF_NODE_ID=e2e-waf",
    "-e",
    "WAF_STATE_DIR=/config/waf-state",
    "-e",
    "WAF_CONFIG=/config/config.json",
    "-v",
    path.join(root, ".artifacts/bin/waf") + ":/waf:ro",
    "-v",
    path.join(root, ".artifacts") + ":/config",
    "-p",
    "127.0.0.1:5181:8081",
    "node:22-bookworm-slim",
    "/waf",
  );
  // Copy the known snapshot to the path used by the WAF process.
  fs.copyFileSync(config, path.join(root, ".artifacts/config.json"));
  await until(async () => {
    const r = await wafRequest("/");
    return r.status === 200;
  }, 25000);
  const attack = await wafRequest("/?q=" + encodeURIComponent("' OR 1=1 --"));
  assert.equal(attack.status, 403);
  await until(async () => {
    const logs = await api("/waf-events");
    return logs.items.find((e) => e.siteId === site.id && e.action === "BLOCK");
  }, 20000);
  assert.ok(
    (await api("/findings?kind=ALERT")).items.some((f) => f.source === "waf"),
  );
  await until(async()=>{const nodes=await api('/waf-nodes');const n=nodes.items.find(n=>n.id==='e2e-waf');return n?.stats?.totalRequests>0;},25000);
 const access=await until(async()=>{const logs=await api('/waf-access?nodeId=e2e-waf');return logs.items.length?logs:null;},25000);assert.ok(access.items.every(e=>e.path==='[redacted]'));
 console.log(
    "WAF real E2E passed: upstream proxy → attack blocked → event ingested → security alert.",
  );
  for (const n of names) docker("rm", "-f", n);
})().catch((e) => {
  console.error(e.message);
  process.exit(1);
});
