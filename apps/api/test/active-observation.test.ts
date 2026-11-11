import test from 'node:test';import assert from 'node:assert/strict';
import {activeProbeOutcome} from '../src/active-scan-runner';
test('native informational matches remain observations without raising software or network risk',()=>{
 assert.equal(activeProbeOutcome('CONFIRMED',{nativeTemplate:{sha256:'a'.repeat(64)}},'INFO'),'OBSERVED');
 assert.equal(activeProbeOutcome('CONFIRMED',{nativeTemplate:{sha256:'a'.repeat(64)}},'MEDIUM'),'CONFIRMED');
 assert.equal(activeProbeOutcome('CONFIRMED',{conditions:[]},'INFO'),'CONFIRMED');
 assert.equal(activeProbeOutcome('INCONCLUSIVE',{nativeTemplate:{}},'INFO'),'INCONCLUSIVE');
 assert.equal(activeProbeOutcome('NOT_FOUND',{nativeTemplate:{}},'INFO'),'NOT_FOUND');
});
