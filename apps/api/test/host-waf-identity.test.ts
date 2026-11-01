import {test} from 'node:test';import assert from 'node:assert/strict';
import {authorizeHostWaf} from '../src/host-waf-identity';
import {hashToken} from '../src/security';
const token='owned-node-token-with-at-least-32-characters';
function fixture(){return {setting:{findUnique:async({where}:any)=>where.key==='host-waf-credential:'+hashToken(token)?{value:{assetId:'asset-a',assetTokenHash:'active'}}:null,findMany:async()=>[{key:'host-waf-site:site-a',value:{assetId:'asset-a'}}]},asset:{findUnique:async()=>({id:'asset-a',tokenHash:'active',archivedAt:null})}} as any}
test('host WAF credentials only accept their assigned sites and node',async()=>{const db=fixture(),req={headers:{authorization:'Bearer '+token}};assert.deepEqual(await authorizeHostWaf(db,req,['site-a'],'host-asset-a'),['site-a']);await assert.rejects(()=>authorizeHostWaf(db,req,['site-b'],'host-asset-a'));await assert.rejects(()=>authorizeHostWaf(db,req,['site-a'],'other-node'));});
test('host WAF credential is invalid after asset revocation',async()=>{const db=fixture();db.asset.findUnique=async()=>({id:'asset-a',tokenHash:null});await assert.rejects(()=>authorizeHostWaf(db,{headers:{authorization:'Bearer '+token}},[]));});
test('unknown component token cannot inspect host assignments',async()=>{await assert.rejects(()=>authorizeHostWaf(fixture(),{headers:{authorization:'Bearer unknown'}},[]));});

test('changing the Agent credential does not reactivate an old WAF credential',async()=>{const db=fixture();db.asset.findUnique=async()=>({id:'asset-a',tokenHash:'new-generation'});await assert.rejects(()=>authorizeHostWaf(db,{headers:{authorization:'Bearer '+token}},[]));});
import {hostingNodes} from '../src/waf-deployments';
test('host sites and central sites acknowledge only their actual hosting nodes',()=>{const nodes=[{id:'central'},{id:'host-asset-a'},{id:'host-asset-b'}];assert.deepEqual(hostingNodes(nodes,{value:{assetId:'asset-a',status:'ACTIVE'}}).map(n=>n.id),['host-asset-a']);assert.deepEqual(hostingNodes(nodes,null).map(n=>n.id),['central']);});
import {supportsHostWaf} from '../src/host-waf';
test('installation feature version checks match actual Agent diagnostics',()=>{assert.equal(supportsHostWaf({agentVersion:'0.4.9'}),true);assert.equal(supportsHostWaf({agentDiagnostics:{version:'0.4.4'}}),false);assert.equal(supportsHostWaf({agentDiagnostics:{version:'0.5.0'}}),true);assert.equal(supportsHostWaf({}),false);});
