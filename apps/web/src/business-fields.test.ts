import {describe,it,expect} from 'vitest';
import {businessFieldHelp,operatingSystems} from './business-fields';
describe('business form guidance',()=>{
 it('explains purpose and impact for the existing shared inputs',()=>{
  for(const key of ['assetId','business','conclusion','config','configKey','description','dueAt','email','evidence','expiresAt','findingId','findingIds','healthService','hostname','ip','items','name','os','owner','path','permission','reason','status','tags','title','upstream','verification','kind','mode','resolved','role','severity','template'])expect(businessFieldHelp(key).length,key).toBeGreaterThan(12);
 });
 it('provides bounded operating system choices and distinguishes unsupported installation platforms',()=>{
  expect(operatingSystems.map(x=>x.value)).toEqual(['linux','windows','darwin','other']);expect(operatingSystems.find(x=>x.value==='linux')?.label).toBe('Linux');expect(businessFieldHelp('os')).toContain('Linux');
 });
});
