import {z} from 'zod';

const time=z.string().regex(/^(?:[01]\d|2[0-3]):[0-5]\d$/,'请选择有效的小时和分钟');
const weekdays=z.array(z.number().int().min(1).max(7)).min(1).max(7).refine(days=>new Set(days).size===days.length,'星期不能重复');
const timezone=z.string().min(1).max(100).refine(value=>{try{new Intl.DateTimeFormat('en',{timeZone:value});return true}catch{return false}},'请选择有效的时区');
const date=z.string().regex(/^\d{4}-\d{2}-\d{2}$/).refine(value=>{const parsed=new Date(value+'T00:00:00Z');return Number.isFinite(+parsed)&&parsed.toISOString().slice(0,10)===value},'请选择真实存在的日期');
const window=z.object({weekdays,start:time,end:time}).strict().refine(value=>value.start!==value.end,'窗口开始与结束不能相同');
const common={timezone,windows:z.array(window).max(20).default([])};
export const scanTimingInput=z.discriminatedUnion('kind',[
 z.object({...common,kind:z.literal('MANUAL')}).strict(),
 z.object({...common,kind:z.literal('INTERVAL'),seconds:z.number().int().min(3600).max(604800)}).strict(),
 z.object({...common,kind:z.literal('ONCE'),date,time}).strict(),
 z.object({...common,kind:z.literal('CALENDAR'),time,weekdays:weekdays.default([1,2,3,4,5,6,7])}).strict(),
]);
export type ScanTiming=z.infer<typeof scanTimingInput>;
export type ScanTimingSkip={date:string;time:string;reason:'DST_GAP'|'OUTSIDE_WINDOW'};
export const scanTimezones=['UTC',...Intl.supportedValuesOf('timeZone')];
function formatter(zone:string){return new Intl.DateTimeFormat('en-CA',{timeZone:zone,calendar:'gregory',numberingSystem:'latn',year:'numeric',month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit',hourCycle:'h23'})}
function civil(f:Intl.DateTimeFormat,at:Date){const parts=Object.fromEntries(f.formatToParts(at).map(part=>[part.type,part.value]));return {date:parts.year+'-'+parts.month+'-'+parts.day,time:parts.hour+':'+parts.minute}}
function dayNumber(day:string){return new Date(day+'T00:00:00Z').getUTCDay()||7}
function dayAfter(day:string,days:number){const value=new Date(day+'T00:00:00Z');value.setUTCDate(value.getUTCDate()+days);return value.toISOString().slice(0,10)}
function windowOpen(timing:Pick<ScanTiming,'timezone'|'windows'>,at:Date,f:Intl.DateTimeFormat){
 if(!timing.windows.length)return true;
 const local=civil(f,at),today=dayNumber(local.date),yesterday=today===1?7:today-1;
 return timing.windows.some(w=>w.start<w.end?w.weekdays.includes(today)&&local.time>=w.start&&local.time<w.end:w.weekdays.includes(today)&&local.time>=w.start||w.weekdays.includes(yesterday)&&local.time<w.end);
}
export function scanWindowOpen(timing:Pick<ScanTiming,'timezone'|'windows'>,at:Date){return windowOpen(timing,at,formatter(timing.timezone))}
// Candidate UTC offsets come from both sides of local transitions. Verify each
// against the requested civil time, so gaps are skipped and folds choose once.
function civilInstants(day:string,clock:string,f:Intl.DateTimeFormat){
 const nominal=Date.parse(day+'T'+clock+':00Z'),offsets=new Set<number>();
 for(let hours=-36;hours<=36;hours+=3){const utc=nominal+hours*3600000,local=civil(f,new Date(utc));offsets.add(Date.parse(local.date+'T'+local.time+':00Z')-utc)}
 return [...offsets].map(offset=>new Date(nominal-offset)).filter(at=>{const local=civil(f,at);return local.date===day&&local.time===clock}).sort((a,b)=>+a-+b);
}
export function nextScanTime(timing:ScanTiming,after:Date):{next:Date|null;skipped:ScanTimingSkip[]}{
 if(!Number.isFinite(+after))throw new Error('调度基准时间无效');
 const skipped:ScanTimingSkip[]=[],f=formatter(timing.timezone);
 if(timing.kind==='MANUAL')return {next:null,skipped};
 if(timing.kind==='INTERVAL'){
  const due=new Date(+after+timing.seconds*1000);
  if(windowOpen(timing,due,f))return {next:due,skipped};
  // Interval due outside a permitted window waits for its next opening. The
  // search is bounded to a weekly cycle plus a transition day.
  let cursor=Math.ceil(+due/60000)*60000;
  for(let minute=0;minute<8*24*60;minute++,cursor+=60000)if(windowOpen(timing,new Date(cursor),f))return {next:new Date(cursor),skipped};
  return {next:null,skipped};
 }
 const first=timing.kind==='ONCE'?timing.date:civil(f,after).date;
 for(let index=0;index<=(timing.kind==='ONCE'?0:14);index++){
  const day=dayAfter(first,index);
  if(timing.kind==='CALENDAR'&&!timing.weekdays.includes(dayNumber(day)))continue;
  const instants=civilInstants(day,timing.time,f);
  if(!instants.length){skipped.push({date:day,time:timing.time,reason:'DST_GAP'});continue}
  const at=instants[0]; // The second occurrence never becomes a second run.
  if(at<=after)continue;
  if(!windowOpen(timing,at,f)){skipped.push({date:day,time:timing.time,reason:'OUTSIDE_WINDOW'});continue}
  return {next:at,skipped};
 }
 return {next:null,skipped};
}
export function planScanTiming(plan:{timing?:unknown;intervalSeconds?:number|null}):ScanTiming{
 if(plan.timing!=null)return scanTimingInput.parse(plan.timing);
 return scanTimingInput.parse(plan.intervalSeconds?{kind:'INTERVAL',timezone:'UTC',seconds:plan.intervalSeconds}:{kind:'MANUAL',timezone:'UTC'});
}
