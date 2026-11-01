import {Button,Form,Select,Typography} from 'antd';
import {PlusOutlined,DeleteOutlined} from '@ant-design/icons';
import {DateField} from './DateField';import {TimeField} from './TimeField';import {ModuleToolbar} from './ModuleSection';
const days=['周一','周二','周三','周四','周五','周六','周日'].map((label,index)=>({value:index+1,label}));
const timezoneNames:Record<string,string>={'Asia/Shanghai':'中国标准时间 · Asia/Shanghai',UTC:'协调世界时 · UTC','America/New_York':'美国东部时间 · America/New_York','Europe/London':'英国时间 · Europe/London'};
export function ScanTimingFields({timezones}:{timezones:string[]}){
 const form=Form.useFormInstance(),kind=Form.useWatch(['timing','kind'],form)||'MANUAL';
 return <>
 <Form.Item name={['timing','kind']} label="运行方式" extra="手动按需执行；固定间隔从本次安排时间计算；日历按所选时区和星期执行，不补发大量错过的历史任务。" rules={[{required:true}]}><Select aria-label="运行方式" options={[{value:'MANUAL',label:'仅手动执行'},{value:'ONCE',label:'指定日期执行一次'},{value:'INTERVAL',label:'固定间隔'},{value:'CALENDAR',label:'按星期与时间执行'}]}/></Form.Item>
 <Form.Item name={['timing','timezone']} label="计划时区" extra="执行日期、星期和允许窗口均使用此时区，与浏览器当前时区无关。夏令时缺失时刻跳过，重复时刻只采用第一次。" rules={[{required:true}]}><Select showSearch optionFilterProp="label" options={timezones.map(value=>({value,label:timezoneNames[value]||value}))}/></Form.Item>
 {kind==='INTERVAL'&&<Form.Item name={['timing','seconds']} preserve={false} initialValue={86400} label="间隔长度" extra="上次安排后至少等待此间隔；到期不在允许窗口时，移到下一允许窗口。相同计划仍不会重叠执行。" rules={[{required:true}]}><Select options={[{value:3600,label:'每小时'},{value:21600,label:'每6小时'},{value:86400,label:'每24小时'},{value:604800,label:'每7天'}]}/></Form.Item>}
 {kind==='ONCE'&&<Form.Item name={['timing','date']} preserve={false} label="执行日期" extra="使用所选计划时区的日期；已过去或因夏令时而不存在的单次时刻不能启用。" rules={[{required:true}]}><DateField/></Form.Item>}
 {['ONCE','CALENDAR'].includes(kind)&&<Form.Item name={['timing','time']} preserve={false} initialValue="02:00" label="执行时间" extra="选择计划时区的小时和分钟。调度器会合并停机期间错过的周期，保留本次实际执行依据。" rules={[{required:true}]}><TimeField/></Form.Item>}
 {kind==='CALENDAR'&&<Form.Item name={['timing','weekdays']} preserve={false} initialValue={[1,2,3,4,5,6,7]} label="执行星期" extra="全部选中表示每天；只选一个或几个星期表示按周执行，至少选择一天。" rules={[{required:true,type:'array',min:1}]}><Select mode="multiple" options={days}/></Form.Item>}
 <div className="module-field-wide"><Typography.Paragraph type="secondary">允许执行窗口可选；不配置时全天允许。手动执行也受窗口约束，窗口结束后保留已完成结果，未完成部分不会显示为检查通过。</Typography.Paragraph>
 <Form.List name={['timing','windows']}>{(fields,{add,remove})=><div className="module-repeat-list">{fields.map(field=><section key={field.key} className="detection-repeat-row"><ModuleToolbar><h3>允许窗口 {field.name+1}</h3><Button aria-label="移除窗口" icon={<DeleteOutlined/>} onClick={()=>remove(field.name)}>移除窗口</Button></ModuleToolbar><div className="module-form-grid">
 <Form.Item name={[field.name,'weekdays']} label="窗口开始星期" extra="窗口可以跨午夜，例如周一22:00至周二02:00，按周一作为开始星期。" rules={[{required:true,type:'array',min:1}]}><Select mode="multiple" options={days}/></Form.Item>
 <Form.Item name={[field.name,'start']} label="窗口开始时间" extra="从此分钟起允许开始或继续检查，使用计划时区。" rules={[{required:true}]}><TimeField/></Form.Item>
 <Form.Item name={[field.name,'end']} label="窗口结束时间" extra="结束时刻不包含在窗口内；早于开始时间表示跨午夜，不能与开始相同。" rules={[{required:true}]}><TimeField/></Form.Item>
 </div></section>)}<Button aria-label="增加允许执行窗口" icon={<PlusOutlined/>} onClick={()=>add({weekdays:[1,2,3,4,5],start:'22:00',end:'06:00'})}>增加允许执行窗口</Button></div>}</Form.List>
 </div>
 </>;
}
export function scanTimingDescription(plan:any){const value=plan.timing;if(!value)return plan.intervalSeconds?'每 '+plan.intervalSeconds/3600+' 小时':'手动执行';return value.kind==='ONCE'?value.date+' '+value.time:value.kind==='CALENDAR'?'每周 '+value.weekdays.map((day:number)=>days[day-1]?.label||day).join('、')+' '+value.time:value.kind==='INTERVAL'?'每 '+value.seconds/3600+' 小时':'手动执行'}

export function scanNextDescription(value:string,plan:any){return new Intl.DateTimeFormat('zh-CN',{timeZone:plan.timing?.timezone||'UTC',year:'numeric',month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit',hourCycle:'h23'}).format(new Date(value))}
export function scanWindowDescription(policy:any){return policy.windows?.length?policy.windows.map((window:any)=>window.weekdays.map((day:number)=>days[day-1]?.label||day).join('、')+' '+window.start+'—'+window.end+(window.start>window.end?'（跨午夜）':'')).join('；'):'全天允许'}
