import {useEffect,useState} from 'react';import {Alert,Form,Select} from 'antd';import {api} from './api';import {HostWafFields} from './HostNetworkPanel';
export function AgentHostWafFields(){
 const[options,setOptions]=useState<any>(),[error,setError]=useState('');const form=Form.useFormInstance(),siteId=Form.useWatch(['hostWaf','siteId'],form);
 useEffect(()=>{let current=true;void(async()=>{try{const me=await api('/auth/me');if(me.role==='ADMIN'){const value=await api('/host-waf/options');if(current)setOptions(value);}}catch(e){if(current)setError((e as Error).message);}})();return()=>{current=false;};},[]);
 if(!options)return error?<Alert className="module-field-wide" type="warning" message="同机 Web 接入选项读取失败" description={error}/>:null;
 return <section className="module-field-wide module-stack"><div><strong>安装后自动接入 Nginx（可选）</strong><p className="module-note">需要 Agent 0.4.9。保留现有 Nginx 入口、域名与证书，由安装程序启动本机自研 WAF，再验证正常请求和检测样本；复杂配置不会自动改写。目标主机需预装 Docker 并具备下方固定摘要镜像。</p></div>
 {!options.image&&<Alert type="warning" showIcon message="先完成 WAF 镜像交付" description="部署管理员设置 HOST_WAF_IMAGE 的固定摘要并交付镜像后，才能授权自动接入。"/>}
 <Form.Item name={['hostWaf','siteId']} label="安装后接入的站点" extra="留空只安装采集器；选择后必须填写站点的真实配置和健康路径。仅管理员可授权，同机接入不要求启用修复执行器。"><Select allowClear disabled={!options.image} onClear={()=>form.setFieldValue('hostWaf',undefined)} placeholder="不自动接入站点" options={options.sites.filter((site:any)=>site.enabled).map((site:any)=>({value:site.id,label:site.name+' · '+site.hostname}))}/></Form.Item>
 {siteId&&<div className="module-form-grid"><HostWafFields prefix={['hostWaf']}/></div>}
 </section>;
}
