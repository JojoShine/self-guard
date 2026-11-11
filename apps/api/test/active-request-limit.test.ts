import test from 'node:test';import assert from 'node:assert/strict';
import {previewRequestLimit,frozenRequestLimit,assertActiveSelectionBudget} from '../src/active-scan-limits';
const endpoints=[{assetId:'a',protocol:'http'}],native={definition:{method:'GET',rule:{nativeTemplate:{},maxRedirects:0}}};
test('broad native preview freezes a sufficient bounded request budget while old plans keep 300',()=>{
 assert.equal(previewRequestLimit(endpoints,Array.from({length:500},()=>native)),500);
 assert.equal(previewRequestLimit(endpoints,Array.from({length:500},()=>native),{}),undefined);
 assert.equal(previewRequestLimit(endpoints,[native]),undefined);
 assert.equal(previewRequestLimit(endpoints,[native],{requestLimit:700}),700);
 assert.throws(()=>previewRequestLimit(Array.from({length:21},()=>endpoints[0]),Array.from({length:500},()=>native)),/10000/);
 assert.equal(frozenRequestLimit({activeSources:{}}),300);
 assert.equal(frozenRequestLimit({activeSources:{requestLimit:500}}),500);
 assert.throws(()=>frozenRequestLimit({activeSources:{requestLimit:10001}}));
});

test('generic selection cannot expand into an unbounded frozen payload or check matrix',()=>{
 const native=[{definition:{rule:{nativeTemplate:{raw:'owned'}}}}];
 assert.doesNotThrow(()=>assertActiveSelectionBudget(native,[],1,2073));
 assert.throws(()=>assertActiveSelectionBudget(native,[],1,10001),/10000/);
 assert.throws(()=>assertActiveSelectionBudget([{definition:{rule:{nativeTemplate:{raw:'x'.repeat(16*1024*1024)}}}}],[],1,1),/预算/);
 assert.throws(()=>assertActiveSelectionBudget([{definition:{rule:{nativeTemplate:{raw:'x'.repeat(1024*1024)}}}}],[],65,65),/预算/);
});
