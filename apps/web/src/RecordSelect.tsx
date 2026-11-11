import {useEffect,useRef,useState} from 'react';
import {Alert,Button,Select,Typography} from 'antd';
import {api} from './api';

type Option={value:string;label:string;disabled?:boolean};
type Props={resource:'assets'|'findings'|'tasks'|'sites'|'businesses'|'database-instances';id?:string;ariaLabel?:string;value?:string|string[];onChange?:(value:any)=>void;mode?:'multiple';maxCount?:number;kind?:string;assetId?:string;allowArchived?:boolean;disabled?:boolean;status?:string;unbatched?:boolean;placeholder?:string};
function option(row:any,allowArchived:boolean):Option{return {value:row.id,label:(row.name||row.hostname||row.title||'未命名记录')+(row.ip?' · '+row.ip:row.name&&row.hostname?' · '+row.hostname:'')+(row.archivedAt?' · 已归档':''),disabled:!allowArchived&&!!row.archivedAt}}
export function RecordSelect({resource,id,ariaLabel,value,onChange,mode,maxCount,kind,assetId,status,unbatched,disabled,allowArchived=true,placeholder='输入名称查找并选择已有记录'}:Props){
 const [open,setOpen]=useState(false),[query,setQuery]=useState(''),[items,setItems]=useState<Option[]>([]),[selected,setSelected]=useState<Option[]>([]),[loading,setLoading]=useState(false),[error,setError]=useState(''),[page,setPage]=useState(0),[total,setTotal]=useState(0);
 const epoch=useRef(0),pending=useRef<number>(),selectedIds=(Array.isArray(value)?value:value?[value]:[]),selectedKey=JSON.stringify(selectedIds);
 const control=useRef<HTMLDivElement>(null),[popupWidth,setPopupWidth]=useState<number>();
 useEffect(()=>{if(!open||!control.current)return;const element=control.current,resize=()=>{if(element.offsetWidth)setPopupWidth(element.offsetWidth)};resize();const observer=new ResizeObserver(resize);observer.observe(element);return()=>observer.disconnect()},[open]);
 useEffect(()=>{let active=true;setSelected([]);if(!selectedIds.length)return;
  const choices:Option[]=[],fetching=async()=>{let index=0;await Promise.all(Array.from({length:Math.min(8,selectedIds.length)},async()=>{while(active&&index<selectedIds.length){const position=index++,recordId=selectedIds[position];try{choices[position]=option((await api('/record-options/'+resource+'?selected='+encodeURIComponent(recordId))).items[0],allowArchived)}catch{choices[position]={value:recordId,label:'记录暂时不可读，请查找并核对',disabled:true}}}}));if(active)setSelected(choices)};void fetching();
  return()=>{active=false};
 },[resource,selectedKey,allowArchived]);
 async function load(next:number,version=epoch.current){if(pending.current===version)return;pending.current=version;setLoading(true);setError('');try{
  const params=new URLSearchParams({page:String(next),pageSize:'15',q:query,...(kind?{kind}:{}),...(assetId?{assetId}:{}),...(status?{status}:{}),...(unbatched?{unbatched:'true'}:{}),...(!allowArchived?{activeOnly:'true'}:{})}),result=await api('/record-options/'+resource+'?'+params);
  if(version!==epoch.current)return;setItems(old=>next===1?result.items.map((row:any)=>option(row,allowArchived)):[...old,...result.items.map((row:any)=>option(row,allowArchived))]);setPage(next);setTotal(result.total);
 }catch(e){if(version===epoch.current)setError((e as Error).message)}finally{if(pending.current===version)pending.current=undefined;if(version===epoch.current)setLoading(false)}}
 useEffect(()=>{const version=++epoch.current;setItems([]);setPage(0);setTotal(0);setError('');if(!open){setLoading(false);return}
  const timer=setTimeout(()=>void load(1,version),query?250:0);return()=>{clearTimeout(timer);epoch.current++};
 },[open,query,resource,kind,assetId,status,unbatched,allowArchived]);
 const options=[...new Map([...selectedIds.map(recordId=>selected.find(row=>row.value===recordId)||{value:recordId,label:'正在读取所选记录…'}),...items].map(row=>[row.value,row])).values()];
 return <div ref={control} style={{width:'100%',minWidth:0}}><Select id={id} aria-label={ariaLabel} style={{width:'100%'}} popupMatchSelectWidth={popupWidth||true} disabled={disabled} value={value} onChange={onChange} mode={mode} maxCount={maxCount} maxTagCount="responsive" allowClear showSearch filterOption={false} searchValue={query} onSearch={setQuery} onOpenChange={next=>{if(next&&control.current?.offsetWidth)setPopupWidth(control.current.offsetWidth);setOpen(next)}} loading={loading} options={options} placeholder={placeholder} notFoundContent={loading?'正在读取记录…':'没有匹配记录，请调整名称或检查授权范围'} popupRender={menu=><>{menu}<div className="record-select-footer" onMouseDown={event=>event.preventDefault()}>
  {error?<><Alert type="error" showIcon message={error}/><Button onClick={()=>void load(page+1)}>重新加载记录</Button></>:<><Typography.Text type="secondary">按名称检索已有记录 · 已加载 {items.length} / {total}</Typography.Text>{items.length<total&&<Button type="link" disabled={loading} onClick={()=>void load(page+1)}>加载更多记录</Button>}</>}
 </div></>}/></div>;
}
