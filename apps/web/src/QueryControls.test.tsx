vi.mock('./api',()=>({api:vi.fn()}));
import {describe,it,expect,vi} from 'vitest';
import {renderToStaticMarkup} from 'react-dom/server';
import {QueryControls,QueryFilterBar,defaultFilters,readLocation,queryParams} from './QueryControls';

describe('date filters',()=>{
 it('renders calendar controls while retaining the selected UTC calendar days',()=>{
  const html=renderToStaticMarkup(<QueryControls resource="findings" value={{...defaultFilters,createdFrom:'2026-10-01T00:00:00.000Z',createdTo:'2026-10-03T23:59:59.999Z'}} onChange={()=>{}}/>);
  expect(html).toContain('ant-picker');
  expect(html).not.toContain('type="date"');
  expect(html).toContain('2026-10-01');
  expect(html).toContain('2026-10-03');
 });
});

describe('shared advanced filters',()=>{
 it('keeps domain pages fixed to their domain even when an old filter conflicts',()=>{
  const html=renderToStaticMarkup(<QueryControls resource="findings" lockedDomain="DATA" value={{...defaultFilters,securityDomain:'NETWORK'}} onChange={()=>{}}/>);
  expect(html).toContain('ant-select-disabled');expect(html).toContain('title="数据安全"');
 });
 it('exposes security domain for findings/discoveries and preserves it in navigation and requests',()=>{
  for(const resource of ['findings','discoveries']){
   const html=renderToStaticMarkup(<QueryControls resource={resource} value={{...defaultFilters,securityDomain:'DATA'}} onChange={()=>{}}/>);
   expect(html).toContain('安全领域');expect(html).toContain('数据安全');
  }
  expect(renderToStaticMarkup(<QueryControls resource="assets" value={defaultFilters} onChange={()=>{}}/>)).not.toContain('安全领域');
  vi.stubGlobal('location',{hash:'#findings?securityDomain=NETWORK'});
  try{expect(readLocation().extra.securityDomain).toBe('NETWORK');}finally{vi.unstubAllGlobals();}
  expect(queryParams('',undefined,undefined,1,{...defaultFilters,securityDomain:'DATA'}).get('securityDomain')).toBe('DATA');
 });
 it('keeps secondary fields collapsed while exposing active condition count',()=>{const html=renderToStaticMarkup(<QueryFilterBar primary={<input aria-label="常用搜索"/>} activeCount={2} onClear={()=>{}}><label>来源主机<input/></label></QueryFilterBar>);expect(html).toContain('常用搜索');expect(html).toContain('aria-expanded="false"');expect(html).toContain('高级筛选 · 2');expect(html).not.toContain('来源主机');});
 it('uses the same expanded condition group and reset action for existing and new lists',()=>{const html=renderToStaticMarkup(<QueryFilterBar primary={<input aria-label="常用搜索"/>} open onOpenChange={()=>{}} onClear={()=>{}} description="选择来源与时间"><label>来源主机<input/></label></QueryFilterBar>);expect(html).toContain('aria-expanded="true"');expect(html).toContain('来源主机');expect(html).toContain('选择来源与时间');expect(html).toContain('清空筛选');});
});
