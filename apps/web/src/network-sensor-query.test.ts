import {it,expect} from 'vitest';import {readSensorLocation,sensorHref,sensorFilterTime,sensorDateValue,sensorEventQuery} from './network-sensor-query';
it('keeps exact event, scope, flow, time and pagination when reloading or navigating back',()=>{const original='#network-sensors?assetId=host&sensorId=sensor&flowId=18446744073709551615&from=2026-11-06T08%3A00%3A00.000Z&to=2026-11-06T09%3A00%3A00.000Z&recordId=event&page=2&pageSize=30';const state=readSensorLocation(original);expect(state).toEqual({filters:{assetId:'host',sensorId:'sensor',flowId:'18446744073709551615',from:'2026-11-06T08:00:00.000Z',to:'2026-11-06T09:00:00.000Z'},recordId:'event',page:2,size:30});expect(readSensorLocation(sensorHref(state))).toEqual(state);expect(readSensorLocation('#network-sensors?recordId=second').recordId).toBe('second');});
it('converts UTC-labelled calendar values to offset-bearing API dates and back without local timezone drift',()=>{expect(sensorFilterTime('2026-11-06T08:15:30')).toBe('2026-11-06T08:15:30.000Z');expect(sensorDateValue('2026-11-06T10:15:30+02:00')).toBe('2026-11-06T08:15:30');expect(sensorFilterTime(undefined)).toBeUndefined();expect(sensorDateValue(undefined)).toBeUndefined();});

it('preserves collection configuration on reload without sending view controls to the event API',async()=>{
 const {sensorEventQuery}=await import('./network-sensor-query');
 const config=readSensorLocation('#network-sensors?assetId=host&view=configuration');
 expect(config).toMatchObject({view:'configuration',filters:{assetId:'host'}});
 expect(sensorHref(config)).toContain('view=configuration');
 expect(sensorEventQuery(config).get('eventType')).toBe('flow');
 expect(sensorEventQuery(config).has('view')).toBe(false);
 expect(sensorEventQuery(readSensorLocation('#network-sensors?eventType=alert&recordId=exact')).get('eventType')).toBe('alert');
 expect(sensorEventQuery(config).has('recordId')).toBe(false);
});

it('keeps all associated protocol types when drilling a bounded connection',()=>{const query=sensorEventQuery(readSensorLocation('#network-sensors?flowId=123&sensorId=one'));expect(query.get('flowId')).toBe('123');expect(query.has('eventType')).toBe(false)});
