vi.mock('./api',()=>({api:vi.fn()}));
import {describe,it,expect,vi} from 'vitest';
import {defaultFilters,queryParams,readLocation} from './QueryControls';
describe('shareable query context',()=>{
 it('opens the workbench for a blank hash',()=>{vi.stubGlobal('location',{hash:''});expect(readLocation().page).toBe('overview');});
 it('round-trips exact filter values and pagination',()=>{const extra={...defaultFilters,sortBy:'title',order:'asc',business:'业务 A',owner:'owner@test.local',createdFrom:'2026-10-01T00:00:00.000Z',createdTo:'2026-10-03T23:59:59.999Z'};const query=queryParams('测试','HIGH','OPEN',3,extra,50);vi.stubGlobal('location',{hash:'#risks?'+query});expect(readLocation()).toEqual({page:'risks',q:'测试',severity:'HIGH',status:'OPEN',number:3,pageSize:50,extra});});
 it('defaults old links and unsupported page sizes to fifteen',()=>{
  for(const hash of ['#assets','#assets?pageSize=0','#assets?pageSize=999','#assets?pageSize=bad']){vi.stubGlobal('location',{hash});expect(readLocation().pageSize).toBe(15);}
  expect(queryParams('',undefined,undefined,1,defaultFilters).get('pageSize')).toBe('15');
 });
});
it('maps the legacy combined rule page to scope maintenance without losing query values',()=>{
 vi.stubGlobal('location',{hash:'#rule-tools?q=legacy&page=2&pageSize=30'});
 expect(readLocation()).toMatchObject({page:'rule-scope',q:'legacy',number:2,pageSize:30});
});
