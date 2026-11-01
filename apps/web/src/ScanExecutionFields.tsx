import {Form,Select,Typography} from 'antd';import type {FormInstance} from 'antd';
export function executionFormValue(plan?:any){return plan?.executionIdentityId?`${plan.executionIdentityId}@${plan.executionIdentityVersion??'missing'}`:'OWNER'}
export function executionBindingFromForm(value:any,catalog:any):{executionIdentityId?:string|null;executionIdentityVersion?:number}{
 const choice=value.executionIdentityChoice||'OWNER';
 if(!Array.isArray(catalog.executionIdentities)||!catalog.canManageIdentities){if(choice!=='OWNER')throw Error('当前账号或服务不能确认所选执行授权，请刷新并由管理员核对；不会自动改用负责人权限');return {}}
 if(choice==='OWNER')return {executionIdentityId:null};
 const identity=catalog.executionIdentities.find((row:any)=>row.enabled&&`${row.id}@${row.version}`===choice);if(!identity)throw Error('所选执行授权已变化或停用，请刷新后明确选择当前版本，再重新预览');
 return {executionIdentityId:identity.id,executionIdentityVersion:identity.version};
}
export function ScanExecutionFields({form,catalog,plan}:{form:FormInstance;catalog:any;plan?:any}){
 const value=Form.useWatch('executionIdentityChoice',form)||form.getFieldValue('executionIdentityChoice')||executionFormValue(plan);if(!Array.isArray(catalog.executionIdentities))return null;
 if(!catalog.canManageIdentities)return <Form.Item label="扫描执行方式" extra="专用执行身份由管理员授予。计划始终受负责人当前权限与自身范围约束。"><Typography.Text>{plan?.executionIdentity?.name||'计划负责人'}</Typography.Text></Form.Item>;
 const choices=[{value:'OWNER',label:'使用计划负责人当前权限',disabled:false},...catalog.executionIdentities.map((row:any)=>({value:`${row.id}@${row.version}`,label:`${row.name} · 授权v${row.version}${row.enabled?'':' · 已停用'}`,disabled:!row.enabled}))];
 if(!choices.some(row=>row.value===value))choices.push({value,label:`${plan?.executionIdentity?.name||'原执行身份'} · 原授权已失效，请重新选择`,disabled:true});
 return <Form.Item name="executionIdentityChoice" label="扫描执行身份" extra="选择管理员已授予的范围及版本；实际目标仍取计划、负责人和该授权的交集。授权变化后必须明确重选，不能自动沿用新范围。" rules={[{required:true,message:'请选择执行方式或明确的执行身份'}]}><Select aria-label="扫描执行身份" options={choices} showSearch optionFilterProp="label"/></Form.Item>;
}
