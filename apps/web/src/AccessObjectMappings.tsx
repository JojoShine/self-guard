import {useState} from 'react';
import {Alert,Button,Form,Input,Select,Table,Typography,Upload} from 'antd';
export type AccessObjectMapping={kind:'HTTP_ROUTE';route:string;methods:string[];objects:{database:string;schema?:string;table?:string;columns:string[]}[]}|{kind:'POSTGRES_COLUMN';database:string;relationOid:number;attributeNumber:number;schema:string;table:string;column:string;observedAt:string};
export const postgresMetadataQuery=`BEGIN READ ONLY;
SELECT COALESCE(jsonb_agg(jsonb_build_object(
 'kind','POSTGRES_COLUMN','database',current_database(),
 'relationOid',c.oid::bigint,'attributeNumber',a.attnum,
 'schema',n.nspname,'table',c.relname,'column',a.attname,
 'observedAt',to_char(statement_timestamp() AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'))),'[]'::jsonb)
FROM pg_catalog.pg_class c
JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
JOIN pg_catalog.pg_attribute a ON a.attrelid=c.oid
WHERE c.relkind IN ('r','p','v','m','f') AND a.attnum>0 AND NOT a.attisdropped
AND n.nspname NOT IN ('pg_catalog','information_schema');
COMMIT;`;
export function parsePostgresMappings(value:unknown):AccessObjectMapping[]{
 if(!Array.isArray(value)||value.length>512)throw new Error('请导入最多512项的 PostgreSQL 元数据数组；可按模式或表缩小导出范围');
 for(const row of value){if(!row||typeof row!=='object'||row.kind!=='POSTGRES_COLUMN'||!['database','schema','table','column','observedAt'].every(k=>typeof row[k]==='string'&&row[k].length>0)||!Number.isInteger(row.relationOid)||row.relationOid<1||row.relationOid>4294967295||!Number.isInteger(row.attributeNumber)||row.attributeNumber<1||row.attributeNumber>32767||!Number.isFinite(Date.parse(row.observedAt)))throw new Error('元数据必须包含数据库、模式、表、字段、对象编号、字段序号和快照时间');}
 return value;
}
export function PostgresMappingsField({value=[],onChange}:{value?:AccessObjectMapping[];onChange?:(value:AccessObjectMapping[])=>void}){
 const[error,setError]=useState('');
 return <div className="module-stack"><Alert type="info" showIcon message="导入只读元数据快照，24小时内用于字段关联" description="在已授权的目标数据库执行下方只读查询，将JSON结果保存为文件后导入。数据库重建、表结构变化后应立即重新导入；过期或缺失编号保持未匹配，不依据SQL或别名猜测。"/><details className="evidence-raw"><summary>查看只读元数据查询</summary><Typography.Paragraph code copyable>{postgresMetadataQuery}</Typography.Paragraph></details><Upload accept=".json,application/json" showUploadList={false} beforeUpload={async file=>{try{if(file.size>2*1048576)throw new Error('元数据文件不能超过2MiB');onChange?.(parsePostgresMappings(JSON.parse(await file.text())));setError('');}catch(e){setError((e as Error).message)}return false}}><Button>导入元数据快照</Button></Upload>{error&&<Alert type="error" showIcon message={error}/>}<Typography.Text type="secondary">已登记 {value.length} 个字段关联；保存后生效。</Typography.Text><Table<AccessObjectMapping> rowKey={(_,i)=>String(i)} size="small" scroll={{x:650}} dataSource={value.slice(0,20)} pagination={false} columns={[{title:'数据对象',render:(_,r)=>r.kind==='POSTGRES_COLUMN'?`${r.database}.${r.schema}.${r.table}.${r.column}`:''},{title:'对象编号 / 字段序号',render:(_,r)=>r.kind==='POSTGRES_COLUMN'?r.relationOid+' / '+r.attributeNumber:''},{title:'快照时间',render:(_,r)=>r.kind==='POSTGRES_COLUMN'?r.observedAt:''}]}/>{value.length>0&&<Button onClick={()=>onChange?.([])}>清空本次对象关联</Button>}</div>;
}
export function HttpMappingFields(){return <Form.List name="objectMappings">{(fields,{add,remove})=><div className="module-stack"><Alert type="info" showIcon message="按精确接口路径登记分类关联" description="这是配置关联，用于风险判断参考，不证明本次请求实际执行了数据库访问。请求方法留空匹配该路径的所有方法；不填写查询参数、通配符或动态模板。"/>{fields.map(field=><div className="module-stack module-subsection" key={field.key}><Form.Item name={[field.name,'kind']} hidden><Input/></Form.Item><div className="module-form-grid"><Form.Item name={[field.name,'route']} label="精确接口路径" rules={[{required:true}]}><Input placeholder="/api/customers/export"/></Form.Item><Form.Item name={[field.name,'methods']} label="请求方法"><Select mode="multiple" options={['GET','HEAD','POST','PUT','PATCH','DELETE','OPTIONS'].map(value=>({value,label:value}))}/></Form.Item><Form.Item name={[field.name,'objects',0,'database']} label="关联库名" rules={[{required:true}]}><Input/></Form.Item><Form.Item name={[field.name,'objects',0,'schema']} label="模式（可选）"><Input/></Form.Item><Form.Item name={[field.name,'objects',0,'table']} label="表或命名空间（可选）"><Input/></Form.Item><Form.Item name={[field.name,'objects',0,'columns']} label="字段（可选）"><Select mode="tags"/></Form.Item></div><Button danger onClick={()=>remove(field.name)}>移除此关联</Button></div>)}<Button onClick={()=>add({kind:'HTTP_ROUTE',route:'',methods:[],objects:[{database:'',columns:[]}]})}>添加接口关联</Button></div>}</Form.List>}
