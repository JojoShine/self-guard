import {Table,Typography} from 'antd';import type {TableColumnsType} from 'antd';import {paginationDefaults} from './pagination';
const hints:Record<number,string>={22:'SSH',53:'DNS',80:'HTTP',443:'HTTPS',1433:'SQL Server',1521:'Oracle',3306:'MySQL / MariaDB',5432:'PostgreSQL',6379:'Redis',8080:'HTTP',8443:'HTTPS',27017:'MongoDB',5236:'达梦',54321:'金仓'};
function isRecord(value:unknown):value is Record<string,unknown>{return value!==null&&typeof value==='object'&&!Array.isArray(value)}
function text(value:unknown){return typeof value==='string'||typeof value==='number'?String(value):'—'}
function processes(row:Record<string,unknown>){return Array.isArray(row.processes)?row.processes.filter(isRecord).filter(p=>typeof p.pid==='number'&&Number.isInteger(p.pid)&&p.pid>0&&typeof p.name==='string').slice(0,8):[]}
export const portSoftwareColumns:TableColumnsType<Record<string,unknown>>=[
 {title:'软件名称',render:(_,row)=>row.identification==='PROCESS_SOCKET'&&processes(row).length&&typeof row.software==='string'?row.software:'未识别'},
 {title:'程序 / PID',render:(_,row)=>processes(row).map(p=>text(p.name)+' / '+text(p.pid)).join('、')||'未取得进程信息'},
 {title:'识别依据',render:(_,row)=>row.identification==='PROCESS_SOCKET'&&processes(row).length?'进程关联':'尚无进程依据'},
 {title:'端口常见用途（未确认）',render:(_,row)=>typeof row.serviceHint==='string'?row.serviceHint:typeof row.port==='number'?hints[row.port]||'—':'—'},
];
export function HostPortInventory({inventory}:{inventory:unknown}){
 if(inventory==='[已隐藏]')return <Typography.Paragraph type="secondary">当前权限不能读取端口清单。</Typography.Paragraph>;
 const ports=isRecord(inventory)&&Array.isArray(inventory.ports)?inventory.ports.filter(isRecord).map((row,index)=>({...row,_key:index})):[];
 return <section className="module-stack" aria-label="监听端口与业务软件"><h3>监听端口与业务软件</h3><Typography.Text type="secondary">软件名称按端口对应的可读取进程识别；常见用途仅根据端口提示，不能确认实际软件。旧 Agent、权限不足或容器隔离时可能无法关联，服务版本仍以软件清单为准。</Typography.Text><Table<Record<string,unknown>> size="small" rowKey="_key" dataSource={ports} pagination={paginationDefaults} scroll={{x:1100}} locale={{emptyText:'尚无监听端口记录，请核对 Agent 采集状态'}} columns={[{title:'端口',dataIndex:'port',render:text},{title:'协议',dataIndex:'protocol',render:text},{title:'监听地址',dataIndex:'address',render:text},...portSoftwareColumns]}/></section>;
}
