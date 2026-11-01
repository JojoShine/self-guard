import {paginationDefaults} from './pagination';
import {useEffect,useState} from 'react';
import {Alert,Button,Descriptions,Space,Switch,Table,Tag,Typography} from 'antd';
import {api} from './api';
import {ModuleSection,ModuleToolbar} from './ModuleSection';
export type RepairTemplate={id:string;name:string;version:string;enabled:boolean;impact:string;parameters:{name:string;required:boolean;description:string}[];preconditions:string[];steps:string[];verification:string[];restore:string[]};
export function TemplateDetails({template}:{template:RepairTemplate}){
 const groups:[string,string[]][]=[['前置检查',template.preconditions],['执行步骤',template.steps],['独立验证',template.verification],['恢复步骤',template.restore]];
 return <Descriptions bordered style={{overflowWrap:"anywhere"}} column={1} size="small"><Descriptions.Item label="参数"><Space direction="vertical">{template.parameters.map(parameter=><span className="template-parameter" key={parameter.name}><Typography.Text code>{parameter.name}</Typography.Text> <Tag>{parameter.required?'必填':'可选'}</Tag>{parameter.description}</span>)}</Space></Descriptions.Item>{groups.map(([label,items])=><Descriptions.Item key={label} label={label}><ol style={{margin:0,paddingLeft:20}}>{items.map((item,index)=><li key={index}>{item}</li>)}</ol></Descriptions.Item>)}</Descriptions>
}
export function TemplatePanel(){
 const[rows,setRows]=useState<RepairTemplate[]>([]),[loading,setLoading]=useState(false),[pending,setPending]=useState(''),[error,setError]=useState(''),[admin,setAdmin]=useState(false);
 async function load(){setLoading(true);setError('');try{const[catalog,user]=await Promise.all([api('/repair-templates'),api('/auth/me')]);setRows(catalog.items);setAdmin(user.role==='ADMIN')}catch(e){setError((e as Error).message)}finally{setLoading(false)}}
 useEffect(()=>{void load()},[]);
 async function toggle(template:RepairTemplate,enabled:boolean){setPending(template.id);setError('');try{const updated=await api('/repair-templates/'+template.id,{enabled},'PATCH');setRows(current=>current.map(row=>row.id===template.id?updated:row))}catch(e){setError((e as Error).message)}finally{setPending('')}}
 return <div className="module-stack">
 {error&&<Alert type="error" message={error} showIcon closable onClose={()=>setError('')}/>}
 <ModuleSection title="受控修复说明"><Alert type="info" showIcon message="受控修复模板" description="模板版本和步骤固定。管理员可停用模板，阻止创建和领取新的修复任务；已领取任务继续按其审批执行。回滚与独立验证仍可用于恢复和核对。Agent 本地允许范围和执行权限始终生效。"/></ModuleSection>
 <ModuleSection title="修复模板目录" description="展开模板查看参数、前置检查、验证和恢复步骤。" extra={<ModuleToolbar><Button onClick={()=>void load()} loading={loading} disabled={!!pending}>刷新模板</Button></ModuleToolbar>}>
 {!admin&&!loading&&<Typography.Paragraph type="secondary">当前账户可查看模板；仅管理员可启用或停用模板。</Typography.Paragraph>}
 <Table<RepairTemplate> scroll={{x:800}} locale={{emptyText:"暂无修复模板"}} rowKey="id" loading={loading} dataSource={rows} pagination={paginationDefaults} expandable={{expandedRowRender:template=><TemplateDetails template={template}/>}} columns={[{title:'模板',width:260,render:(_,template)=><Space direction="vertical" size={0}><Typography.Text className="module-record-title">{template.name}</Typography.Text><Typography.Text code>{template.id}</Typography.Text></Space>},{title:'版本',dataIndex:'version',render:version=><Tag>v{version}</Tag>},{title:'影响范围',dataIndex:'impact'},{title:'启用',render:(_,template)=><Switch checked={template.enabled} checkedChildren="启用" unCheckedChildren="停用" disabled={!admin||loading||!!pending} loading={pending===template.id} onChange={value=>void toggle(template,value)}/>}]} />
 </ModuleSection>
 </div>
}
