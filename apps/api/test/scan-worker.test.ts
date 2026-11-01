import {test} from 'node:test';import assert from 'node:assert/strict';import {Readable} from 'node:stream';import {readProbeFrames} from '../src/scan-worker';
test('probe worker frames preserve Unicode across chunks and reject partial, oversized or malformed output',async()=>{
 const bytes=Buffer.from('{"kind":"CHECK_RESULT","description":"实际检测"}\n');async function* parts(){for(const byte of bytes)yield Buffer.from([byte])}const frames=[];for await(const value of readProbeFrames(parts()))frames.push(value);assert.equal(frames[0].description,'实际检测');
 for(const bytes of [Buffer.from('{}'),Buffer.from('not json\n'),Buffer.from('{"x":"'+'a'.repeat(256*1024)+'"}\n'),Buffer.from([0xff,10])]){await assert.rejects(async()=>{for await(const _ of readProbeFrames(Readable.from([bytes]))){} });}
});
