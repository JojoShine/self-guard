import {Form,Select} from 'antd';
import {assetOSChoices} from './asset-os';
export function AssetOperatingSystemFields(){
 const form=Form.useFormInstance(),choiceId=Form.useWatch('osChoice',form),version=Form.useWatch('osVersion',form),choice=assetOSChoices.find(c=>c.value===choiceId);
 const options=['国产主流 Linux','常见 Linux 发行版','其他系统'].map(label=>({label,options:assetOSChoices.filter(c=>c.group===label).map(c=>({value:c.value,label:c.label}))}));
 if(choiceId?.startsWith('legacy:'))options.push({label:'原有登记值',options:[{value:choiceId,label:choiceId.slice(7)}]});
 const versions=Array.from(new Set([...(choice?.versions||[]),...(version?[version]:[])]));
 return <><Form.Item name="os" hidden><Select/></Form.Item><Form.Item name="osDistribution" hidden><Select/></Form.Item>
 <Form.Item name="osChoice" label="操作系统" extra="选择实际发行版；国产系统、CentOS、Ubuntu 等按类别提供。此处为资产登记，不代表检测或安装兼容性。" rules={[{required:true,message:'请选择操作系统发行版'}]}><Select showSearch optionFilterProp="label" options={options} onChange={value=>{const next=assetOSChoices.find(c=>c.value===value);form.setFieldsValue({os:next?.family||value.slice(7),osDistribution:next&&next.value!==next.family?next.value:null,osVersion:null});}}/></Form.Item>
 <Form.Item name="osVersion" label="发行版本" extra="请选择主机实际版本；不确定或选项中没有时可留空，由 Agent 上报完整版本。切换系统后需重新选择版本。"><Select allowClear options={versions.map(value=>({value,label:choiceId==='uos'&&!/^v/i.test(value)?'V'+value:value}))} placeholder="请选择发行版本（可留空）" onClear={()=>form.setFieldValue('osVersion',null)} disabled={!choiceId||(!versions.length)}/></Form.Item></>;
}
