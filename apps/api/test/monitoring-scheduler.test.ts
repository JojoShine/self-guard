import 'reflect-metadata';import {test,mock} from 'node:test';import assert from 'node:assert/strict';import {Db} from '../src/db';import {Platform} from '../src/platform';import {PostgresMonitoringService} from '../src/postgres-monitor';
test('scheduler drains more than twenty due instances without exceeding two concurrent checks',async()=>{
 const real=new Db(),pending=Array.from({length:23},(_,i)=>({id:String(i)}));let active=0,peak=0,completed=0;const db=new Proxy(real,{get(target,key,receiver){if(key==='monitoringSample')return{deleteMany:async()=>({count:0})};if(key==='operationalMonitor')return{findMany:async(args:{where:{kind:string}})=>args.where.kind==='HOST'?[]:pending.slice(0,10)};return Reflect.get(target,key,receiver)}}),service=new PostgresMonitoringService(db,new Platform(db));
 const methods=[mock.method(service,'poll',async(id:string)=>{active++;peak=Math.max(peak,active);await new Promise(r=>setTimeout(r,1));pending.splice(pending.findIndex(p=>p.id===id),1);active--;completed++;return{checked:true,success:true}})];
 try{await service.tick();assert.equal(completed,23);assert.equal(peak,2)}finally{methods.forEach(m=>m.mock.restore());await db.$disconnect()}
});
