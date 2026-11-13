import {test} from 'node:test';
import assert from 'node:assert/strict';
import {Db} from '../src/db';
import {InstallationService} from '../src/installations';
import {SshInstallationService} from '../src/ssh-installations';
import {markPublicReadOnlyUser} from '../src/public-demo';
test('public metadata readers see installation history globally without expanding ordinary viewers',async()=>{
 const db=new Db(),queries:Record<string,unknown>[]=[];
 const delegate={findMany:async({where}:{where:Record<string,unknown>})=>{queries.push(where);return[];},count:async()=>0};
 Object.defineProperty(db,'agentInstallation',{value:delegate});Object.defineProperty(db,'agentInstallBatch',{value:delegate});const installs=new InstallationService(db),ssh=new SshInstallationService(db,installs);
 const ordinary={id:'viewer',role:'VIEWER',dataScope:{restricted:false}},reader=markPublicReadOnlyUser({...ordinary});
 try{await installs.listInstallations(ordinary,{});await installs.listInstallations(reader,{});await ssh.list(ordinary,{});await ssh.list(reader,{});assert.equal(queries[0].ownerId,'viewer');assert.equal(queries[1].ownerId,undefined);assert.equal(queries[2].ownerId,'viewer');assert.equal(queries[3].ownerId,undefined);}finally{await db.$disconnect();}
});
