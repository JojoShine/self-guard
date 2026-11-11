import {test} from 'node:test';
import assert from 'node:assert/strict';
import {discoveredEndpoints} from '../src/asset-discovery';
import {classificationInput,classificationBasis,activityInput} from '../src/data-governance';
import {databaseActivityInput,databaseRuleCatalog} from '../src/data-security';
test('discovery deduplicates observed endpoints and refuses unspecified and loopback peers',()=>{
 const rows=discoveredEndpoints({ports:[{address:'0.0.0.0',port:3306,protocol:'tcp',state:'LISTEN'}],connections:[{address:'10.0.0.20',port:5432,protocol:'tcp'},{address:'10.0.0.20',port:5432,protocol:'tcp'},{address:'127.0.0.1',port:80,protocol:'tcp'},{address:'0.0.0.0',port:80,protocol:'tcp'}]},'10.0.0.10');
 assert.equal(rows.length,1);assert.equal(rows[0].address,'10.0.0.20');assert.equal(rows[0].basis,'ESTABLISHED');
 assert.equal(discoveredEndpoints({ports:[{address:'0.0.0.0',port:80,protocol:'tcp'}]},null).length,0);
});
test('classification uses highest matching level including column ancestors and never guesses missing objects',()=>{
 const event=activityInput.parse({service:'oracle',database:'billing',schema:'APP',table:'PAYMENT',columns:['CARD'],operation:'SELECT',user:'report',sourceIp:'192.0.2.1'});
 const common={assetId:'asset',engine:'oracle',database:'billing',schema:'',table:'',column:'',category:'业务数据',version:1,handling:'仅授权导出'};
 const definitions=[{...common,id:'db',level:2},{...common,id:'column',schema:'APP',table:'PAYMENT',column:'CARD',level:5},{...common,id:'other',schema:'APP',table:'PAYMENT',column:'CVV',level:5}];
 const basis=classificationBasis(event,definitions,'MEDIUM');assert.equal(basis.level,5);assert.equal(basis.severity,'CRITICAL');assert.deepEqual(basis.definitions.map(d=>d.id),['db','column']);
 assert.equal(classificationBasis({...event,table:undefined,columns:[]},definitions,'HIGH').level,2);
 assert.equal(classificationBasis({...event,database:'other'},definitions,'HIGH').status,'UNCLASSIFIED');
 assert.throws(()=>classificationInput.parse({...common,level:6}));
});
test('six engines have admission and behavior templates and strictly scoped activity rules',()=>{
 for(const engine of ['oracle','mysql','postgresql','sqlserver','dm','kingbase']){
  for(const category of ['ADMISSION','BEHAVIOR'])assert.ok(databaseRuleCatalog.some(r=>r.category===category&&r.engines.includes(engine)));
 }
 assert.ok(databaseActivityInput.safeParse({type:'DATABASE_ACTIVITY',instanceId:'00000000-0000-4000-8000-000000000001',service:'audit-json',path:'/audit.json',engines:['dm'],operations:['GRANT'],threshold:1,windowSeconds:60}).success);
 assert.ok(!databaseActivityInput.safeParse({type:'DATABASE_ACTIVITY',service:'mysql',path:'/audit.json',engines:[],operations:['SQL'],threshold:1,windowSeconds:60}).success);
});
test('one event retains all object classification matches without duplicate event ids',()=>{
 const base={id:'one',engine:'mysql',database:'orders',schema:'app',table:'payments',column:'',category:'财务数据',level:4,handling:'restricted',version:1};
 const event=activityInput.parse({service:'mysql',operation:'SELECT',user:'app',objects:[{database:'orders',schema:'app',table:'payments',columns:[]},{database:'people',schema:'app',table:'profile',columns:['id']}]});
 const basis=classificationBasis(event,[base,{...base,id:'two',database:'people',table:'profile',column:'id',level:5}],'MEDIUM');assert.equal(basis.level,5);assert.equal(basis.definitions.length,2);
});
test('a classified table does not hide an unclassified sibling object in the same database',()=>{const event=activityInput.parse({service:'mysql',operation:'SELECT',user:'app',objects:[{database:'orders',schema:'app',table:'known'},{database:'orders',schema:'app',table:'unknown'}]});const basis=classificationBasis(event,[{id:'known',engine:'mysql',database:'orders',schema:'app',table:'known',column:'',category:'业务数据',level:4,handling:'restricted',version:1}],'INFO');assert.equal(basis.status,'PARTIAL');});

test('partial column classification does not claim the whole requested column set is classified',()=>{const event=activityInput.parse({service:'mysql',operation:'SELECT',user:'app',database:'orders',table:'payments',columns:['a','b']});const definition={id:'a',engine:'mysql',database:'orders',schema:'',table:'payments',column:'a',category:'业务数据',level:4,handling:'restricted',version:1};assert.equal(classificationBasis(event,[definition],'INFO').status,'PARTIAL');assert.equal(classificationBasis(event,[definition,{...definition,id:'parent',column:''}],'INFO').status,'CLASSIFIED');});

test('host discovery excludes local binds, wildcards, loopback, link-local and multicast peers',()=>{
 const ports=['0.0.0.0','::','127.0.0.1','::1','10.0.0.10','10.0.0.5'].map(address=>({address,port:80,protocol:'tcp'}));
 const connections=['0.0.0.0','::','0:0:0:0:0:0:0:1','127.1.2.3','::ffff:127.0.0.1','10.0.0.10','10.0.0.5','169.254.10.1','fe80::1','224.0.0.1','ff02::1','255.255.255.255','10.1.1.3'].map(address=>({address,port:443,protocol:'tcp'}));
 assert.deepEqual(discoveredEndpoints({ports,connections},'10.0.0.10').map(r=>r.address),['10.1.1.3']);
});
