import {TimePicker} from 'antd';
import dayjs from 'dayjs';
export function TimeField({value,onChange,id,disabled}:{value?:string;onChange?:(value:string|undefined)=>void;id?:string;disabled?:boolean}){
 const selected=value?dayjs('2000-01-01T'+value+':00'):null;
 return <TimePicker id={id} disabled={disabled} value={selected?.isValid()?selected:null} format="HH:mm" inputReadOnly showNow={false} style={{width:'100%'}} placeholder="选择小时和分钟" onChange={next=>onChange?.(next?next.format('HH:mm'):undefined)}/>;
}
