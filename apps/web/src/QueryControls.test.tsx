vi.mock('./api',()=>({api:vi.fn()}));
import {describe,it,expect,vi} from 'vitest';
import {renderToStaticMarkup} from 'react-dom/server';
import {QueryControls,defaultFilters} from './QueryControls';

describe('date filters',()=>{
 it('renders calendar controls while retaining the selected UTC calendar days',()=>{
  const html=renderToStaticMarkup(<QueryControls resource="findings" value={{...defaultFilters,createdFrom:'2026-10-01T00:00:00.000Z',createdTo:'2026-10-03T23:59:59.999Z'}} onChange={()=>{}}/>);
  expect(html).toContain('ant-picker');
  expect(html).not.toContain('type="date"');
  expect(html).toContain('2026-10-01');
  expect(html).toContain('2026-10-03');
 });
});
