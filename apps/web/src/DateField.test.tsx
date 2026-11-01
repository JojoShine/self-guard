vi.mock('./api',()=>({api:vi.fn()}));
import {describe,it,expect,vi} from 'vitest';
import dayjs from 'dayjs';
import {DateField} from './DateField';
import {QueryControls,defaultFilters} from './QueryControls';

describe('calendar value contracts',()=>{
 it('keeps selected dates as calendar days and lets optional fields clear',()=>{
  const onChange=vi.fn();
  const field=DateField({value:'2026-10-31',onChange});
  expect(field.props.value.format('YYYY-MM-DD')).toBe('2026-10-31');
  field.props.onChange(dayjs('2026-11-02'));
  expect(onChange).toHaveBeenLastCalledWith('2026-11-02');
  field.props.onChange(null);
  expect(onChange).toHaveBeenLastCalledWith(undefined);
 });
 it('keeps date-time selections in local time for the existing ISO submission handlers',()=>{
  const onChange=vi.fn();
  const field=DateField({showTime:true,onChange});
  field.props.onChange(dayjs('2026-11-02T09:15:30'));
  expect(onChange).toHaveBeenCalledWith('2026-11-02T09:15:30');
  expect(new Date(onChange.mock.calls[0][0]).getHours()).toBe(9);
 });
 it('uses UTC start/end of day for query filters and removes cleared bounds',()=>{
  const onChange=vi.fn();
  const controls=QueryControls({resource:'findings',value:defaultFilters,onChange});
  const fields=controls.props.children.flatMap((child:any)=>child?.props?.children||[]).filter((child:any)=>child?.type===DateField);
  fields[0].props.onChange('2026-11-02');
  expect(onChange).toHaveBeenLastCalledWith({...defaultFilters,createdFrom:'2026-11-02T00:00:00.000Z'});
  fields[1].props.onChange('2026-11-02');
  expect(onChange).toHaveBeenLastCalledWith({...defaultFilters,createdTo:'2026-11-02T23:59:59.999Z'});
  fields[1].props.onChange(undefined);
  expect(onChange).toHaveBeenLastCalledWith({...defaultFilters,createdTo:undefined});
 });
});
