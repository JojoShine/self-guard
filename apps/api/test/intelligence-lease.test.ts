import {test} from 'node:test';import assert from 'node:assert/strict';import {withIntelligenceLease} from '../src/intelligence-lease';import {withRawArchive,onSourceAbort} from '../src/intelligence-artifacts';
test('network-phase ownership renews an unexpired lease and cancels reads after the database revokes it',async()=>{
 let calls=0,cancelled=false;const db={vulnerabilityFeed:{async updateMany(args:any){calls++;assert.equal(args.where.leaseId,'held');assert.ok(args.where.leaseUntil.gt instanceof Date);return {count:calls===1?1:0}}}};
 await withRawArchive(1024,()=>withIntelligenceLease(db,{id:'feed',configHash:'scope'},'held',async()=>{await new Promise<void>(resolve=>{const remove=onSourceAbort(()=>{cancelled=true;remove();resolve()});setTimeout(resolve,100)});assert.equal(cancelled,true)},5));assert.ok(calls>=2);const after=calls;await new Promise(resolve=>setTimeout(resolve,20));assert.equal(calls,after);
});
