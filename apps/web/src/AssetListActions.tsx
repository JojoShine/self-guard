import {Button,Dropdown,Space} from 'antd';import {MoreOutlined} from '@ant-design/icons';
export type AssetActionMode='capture'|'network'|'executor'|'archive'|'connection'|'install';
export function AssetListActions({record,role,evidenceAllowed,onEdit,onOpen}:{record:any;role:string;evidenceAllowed:boolean;onEdit:()=>void;onOpen:(mode:AssetActionMode)=>void}){
 const canEdit=['ADMIN','ANALYST'].includes(role),canManage=['ADMIN','OPERATOR'].includes(role),items=[
 ...(canManage?[{key:'connection',label:'主机管理连接'},{key:'install',label:'远程安装 Agent'}]:[]),
 ...(canManage?[{key:'capture',label:'监测设置与临时抓包'}]:[]),

 ...(canEdit?[{key:'archive',label:record.archivedAt?'恢复资产':'归档资产',danger:!record.archivedAt}]:[]),
 ];
 if(!canEdit&&!canManage)return evidenceAllowed?<Button onClick={()=>onOpen('network')}>网络结果</Button>:null;
 return <Space wrap size={8}>
 {canEdit&&<Button onClick={onEdit}>编辑配置</Button>}
 {evidenceAllowed&&<Button onClick={()=>onOpen('network')}>流量详情</Button>}
 {!!items.length&&<Dropdown trigger={['click']} menu={{items,onClick:({key})=>onOpen(key as AssetActionMode)}}><Button icon={<MoreOutlined/>} aria-label="更多操作">更多</Button></Dropdown>}
 </Space>;
}
