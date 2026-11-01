import {paginationDefaults,pageWithinTotal} from './pagination';
import {useEffect,useState} from 'react';
import {api} from './api';
import {Alert,Button,Table} from 'antd';
import {ModuleToolbar} from './ModuleSection';
import {formatTime} from './presentation';

export function AssetHistoryPanel({id,onInspect}:{id:string;onInspect?:(value:unknown,title:string)=>void}){
 const[data,setData]=useState<any>({assetId:id,items:[],total:0}),[query,setQuery]=useState({id,page:1,pageSize:paginationDefaults.defaultPageSize}),[error,setError]=useState(''),[loading,setLoading]=useState(true),[revision,setRevision]=useState(0);
 const page=query.id===id?query.page:1;
 const pageSize=query.pageSize;
 useEffect(()=>{
  let active=true;
  setLoading(true);setError('');setData({assetId:id,items:[],total:0});
  api('/asset-changes?assetId='+encodeURIComponent(id)+'&page='+page+'&pageSize='+pageSize).then(x=>{if(active){const validPage=pageWithinTotal(page,x.total,pageSize);if(validPage!==page){setQuery({id,page:validPage,pageSize});return;}setData({...x,assetId:id})}}).catch(e=>{if(active)setError(e.message)}).finally(()=>{if(active)setLoading(false)});
  return()=>{active=false};
 },[id,page,pageSize,revision]);
 return <div className="module-stack">
  <ModuleToolbar><h3 style={{margin:0,fontSize:16}}>资产变更历史</h3><Button loading={loading} onClick={()=>setRevision(value=>value+1)}>刷新历史</Button></ModuleToolbar>
  {error&&<Alert type="error" showIcon message={error}/>}
  <Table<any> rowKey="id" loading={loading} scroll={{x:650}} locale={{emptyText:'暂无资产变更记录'}} dataSource={data.assetId===id?data.items:[]} columns={[
   {title:'时间',dataIndex:'createdAt',width:200,render:formatTime},
   {title:'来源',dataIndex:'actor',width:160},
   {title:'变更项',render:(_,r)=>Object.keys(r.changes||{}).join('、')||'—'},
   ...(onInspect?[{title:'操作',render:(_:unknown,r:any)=><Button onClick={()=>onInspect(r.changes,'资产变更依据 · '+formatTime(r.createdAt))}>查看变更</Button>}]:[]),
  ]} pagination={{...paginationDefaults,current:page,total:data.assetId===id?data.total:0,onChange:(next,size)=>setQuery({id,page:size===pageSize?next:1,pageSize:size}),pageSize,showTotal:total=>`共 ${total} 条变更`}}/>
 </div>;
}
