import {expect,it} from 'vitest';import {statusOptions} from './status-options';
it('offers only valid next workflow steps and preserves independent risk verification',()=>{
 expect(statusOptions('findings','RISK','VERIFYING')).toEqual(['IN_PROGRESS']);expect(statusOptions('findings','RISK','IN_PROGRESS')).not.toContain('CLOSED');expect(statusOptions('incidents','','VERIFYING')).toEqual(['CLOSED','IN_PROGRESS']);expect(statusOptions('findings','ALERT','OPEN')).toContain('RESOLVED');expect(statusOptions('findings','unknown','OPEN')).toEqual([]);
});
