import {DatePicker} from 'antd';
import type {DatePickerProps} from 'antd';
import dayjs from 'dayjs';
import 'dayjs/locale/zh-cn';

// Keep the existing string-valued forms and their UTC/local-time contracts.
export function DateField({value,onChange,showTime=false,...props}:Pick<DatePickerProps,'id'|'aria-label'|'disabled'> & {value?:string;onChange?:(value:string|undefined)=>void;showTime?:boolean}){
 const selected=value?dayjs(value):null;
 return <DatePicker {...props} popupClassName="sg-date-popup" style={{width:'100%'}} value={selected?.isValid()?selected:null} showTime={showTime?{format:'HH:mm:ss'}:false} format={showTime?'YYYY-MM-DD HH:mm:ss':'YYYY-MM-DD'} placeholder={showTime?'请选择日期与时间':'请选择日期'} onChange={next=>onChange?.(next?next.format(showTime?'YYYY-MM-DDTHH:mm:ss':'YYYY-MM-DD'):undefined)}/>;
}
