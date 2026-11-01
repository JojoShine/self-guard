import {useState} from 'react';import {Alert,Button,Input,Table,Tabs,Typography} from 'antd';import {EvidenceView} from './EvidenceView';import {ModuleToolbar} from './ModuleSection';import {paginationDefaults,pageWithinTotal} from './pagination';
const formats:Record<string,string>={NPM_INSTALLED_TREE:'npm已安装目录',PYTHON_SITE_PACKAGES:'Python已安装分发',MAVEN_JAR:'Java制品坐标',GO_BINARY:'Go构建信息',NPM_LOCK_FILE:'npm锁文件',CYCLONEDX_1_6:'CycloneDX1.6 SBOM'};
const provenance:Record<string,string>={INSTALLED_METADATA:'实际部署元数据',LOCK_FILE:'锁文件（候选）',SBOM:'SBOM（候选）'};
function label(map:Record<string,string>,value:unknown){const key=String(value||'');return Object.hasOwn(map,key)?map[key]:key||'来源未记录'}
export function AssetInventoryView({inventory,onInspect}:{inventory:any;onInspect?:(value:unknown,title:string)=>void}){
 const [tab,setTab]=useState(inventory?.components?.length?'components':'packages'),[q,setQ]=useState(''),[page,setPage]=useState(1),[size,setSize]=useState(15);
 if(!inventory||typeof inventory!=='object'||Array.isArray(inventory))return <EvidenceView value={inventory} title="采集清单"/>;
 const {components,packages,componentCollection,...other}=inventory,applications=Array.isArray(components)?components:[],system=Array.isArray(packages)?packages:[],rows=(tab==='components'?applications:system).map((row:any,index:number)=>({...row,_key:index})).filter((row:any)=>[row.name,row.version,row.ecosystem,row.origin,row.path].some(value=>String(value||'').toLowerCase().includes(q.toLowerCase())));
 const table=<Table<any> size="small" rowKey="_key" dataSource={rows} scroll={{x:900}} pagination={{...paginationDefaults,current:pageWithinTotal(page,rows.length,size),pageSize:size,total:rows.length,onChange:(next,count)=>{setPage(size===count?next:1);setSize(count)}}} columns={[
 {title:'软件名称',dataIndex:'name',render:(name,row)=>onInspect?<Button type="link" className="record-title-link" onClick={()=>onInspect(Object.fromEntries(Object.entries(row).filter(([key])=>key!=='_key')),'版本与位置依据 · '+(name||'名称未记录'))}>{name||'名称未记录'}</Button>:name||'名称未记录'},{title:'版本',dataIndex:'version'},{title:tab==='components'?'软件生态':'包管理器',render:(_,row)=>tab==='components'?row.ecosystem:row.manager||'来源未记录'},{title:'版本依据',render:(_,row)=>tab==='components'?label(provenance,row.provenance):'已安装软件包清单'},{title:tab==='components'?'实际输入位置':'源软件包',render:(_,row)=>tab==='components'?row.path||'路径未记录':row.origin||'源包未记录'},
 ]}/>;
 return <div className="module-stack asset-inventory-view"><h3>软件与应用清单</h3><Typography.Paragraph type="secondary">查看软件或版本依据时，点击软件名称。这里展示 Agent 本次读取的内容；锁文件和 SBOM 保留为候选依据，不能替代安装事实，也不表示已发生网络利用。</Typography.Paragraph>
 {componentCollection?.complete===false&&<Alert type="warning" showIcon message="应用清单尚不完整" description={componentCollection.reason||'部分输入无法完整读取，请核对下方采集说明。'}/>}
 {Array.isArray(componentCollection?.inputs)&&componentCollection.inputs.length>0&&<section className="module-stack"><h4>应用采集输入及覆盖说明</h4><Table<any> size="small" rowKey={row=>row.format+'|'+row.path} dataSource={componentCollection.inputs} scroll={{x:600}} pagination={{...paginationDefaults}} columns={[{title:'格式',dataIndex:'format',render:value=>label(formats,value)},{title:'输入路径',dataIndex:'path'},{title:'读取结果',render:(_,row)=>row.complete?'已按格式读取':'无法完整读取'},{title:'说明',dataIndex:'reason'}]}/></section>}
 <ModuleToolbar><Input.Search aria-label="查找采集软件" placeholder="按软件、版本、生态或位置查找" allowClear style={{width:320,maxWidth:'100%'}} onSearch={value=>{setQ(value.trim());setPage(1)}}/></ModuleToolbar>
 <Tabs activeKey={tab} onChange={value=>{setTab(value);setPage(1)}} items={[{key:'packages',label:'系统软件包 · '+system.length,children:tab==='packages'?table:null},{key:'components',label:'应用组件 · '+applications.length,children:tab==='components'?table:null}]}/>

 <EvidenceView value={other} title="其他采集与运行信息"/>
 </div>;
}
