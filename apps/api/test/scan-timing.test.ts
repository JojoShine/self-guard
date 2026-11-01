import {test} from 'node:test';import assert from 'node:assert/strict';
import {scanTimingInput,nextScanTime,scanWindowOpen} from '../src/scan-timing';
const now=(value:string)=>new Date(value);

test('calendar uses its explicit timezone and skips a duplicate civil time after the first occurrence',()=>{
 const daily=scanTimingInput.parse({kind:'CALENDAR',timezone:'America/New_York',time:'01:30'});
 assert.equal(nextScanTime(daily,now('2026-11-01T04:00:00Z')).next?.toISOString(),'2026-11-01T05:30:00.000Z');
 assert.equal(nextScanTime(daily,now('2026-11-01T05:45:00Z')).next?.toISOString(),'2026-11-02T06:30:00.000Z');
 const once=scanTimingInput.parse({kind:'ONCE',timezone:'America/New_York',date:'2026-11-01',time:'01:30'});
 assert.equal(nextScanTime(once,now('2026-11-01T05:45:00Z')).next,null);
 const kathmandu=scanTimingInput.parse({kind:'CALENDAR',timezone:'Asia/Kathmandu',time:'09:00'});
 assert.equal(nextScanTime(kathmandu,now('2026-11-01T00:00:00Z')).next?.toISOString(),'2026-11-01T03:15:00.000Z');
});

test('nonexistent daylight-saving slots are recorded and skipped rather than shifted',()=>{
 const schedule=scanTimingInput.parse({kind:'CALENDAR',timezone:'America/New_York',time:'02:30'});
 const result=nextScanTime(schedule,now('2027-03-14T00:00:00Z'));
 assert.equal(result.next?.toISOString(),'2027-03-15T06:30:00.000Z');
 assert.deepEqual(result.skipped,[{date:'2027-03-14',time:'02:30',reason:'DST_GAP'}]);
});

test('weekly dates, midnight-crossing maintenance windows and interval deferral have explicit boundaries',()=>{
 const weekly=scanTimingInput.parse({kind:'CALENDAR',timezone:'UTC',time:'09:00',weekdays:[1,5]});
 assert.equal(nextScanTime(weekly,now('2026-11-02T10:00:00Z')).next?.toISOString(),'2026-11-06T09:00:00.000Z');
 const windows=[{weekdays:[1],start:'22:00',end:'02:00'}];
 assert.equal(scanWindowOpen({timezone:'UTC',windows},now('2026-11-03T01:59:00Z')),true);
 assert.equal(scanWindowOpen({timezone:'UTC',windows},now('2026-11-03T02:00:00Z')),false);
 assert.equal(scanWindowOpen({timezone:'UTC',windows},now('2026-11-03T22:30:00Z')),false);
 const interval=scanTimingInput.parse({kind:'INTERVAL',timezone:'UTC',seconds:3600,windows:[{weekdays:[1,2,3,4,5],start:'09:00',end:'17:00'}]});
 assert.equal(nextScanTime(interval,now('2026-11-02T20:00:00Z')).next?.toISOString(),'2026-11-03T09:00:00.000Z');
 assert.equal(nextScanTime(scanTimingInput.parse({kind:'MANUAL',timezone:'UTC'}),new Date()).next,null);
});

test('invalid timezone, dates, ambiguous schedules and empty windows cannot enter storage',()=>{
 for(const value of [
  {kind:'ONCE',timezone:'UTC',date:'2027-02-30',time:'09:00'},
  {kind:'CALENDAR',timezone:'invalid-zone',time:'09:00'},
  {kind:'CALENDAR',timezone:'UTC',time:'24:00'},
  {kind:'CALENDAR',timezone:'UTC',time:'09:00',weekdays:[]},
  {kind:'CALENDAR',timezone:'UTC',time:'09:00',weekdays:[1,1]},
  {kind:'INTERVAL',timezone:'UTC',seconds:1},
  {kind:'MANUAL',timezone:'UTC',windows:[{weekdays:[1],start:'09:00',end:'09:00'}]},
 ])assert.equal(scanTimingInput.safeParse(value).success,false,JSON.stringify(value));
});
