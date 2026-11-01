export function installationTransportData(row:{status:string;assetId?:string|null},status:string,detail:string){
 if(['SUCCEEDED','CANCELLED','RECOVERING','RECOVERED','FAILED'].includes(row.status))return undefined;
 if(!['FAILED','UNKNOWN','PARTIAL'].includes(status))return undefined;
 return {status:status==='FAILED'&&row.assetId?'UNKNOWN':status,detail};
}
// Retain fixed explanations, never arbitrary remote output, URLs or secrets.
export function installationDiagnostic(text:string):{detail:string;uncertain:boolean}|undefined{
 const matches=[...text.matchAll(/^SELFGUARD_INSTALL_FAILED:(PREPARE|PLATFORM|DOWNLOAD|VERIFY|INSTALL):(\d{1,3})\r?$/gm)],last=matches.at(-1);if(!last)return;
 const stage=last[1],code=Number(last[2]),uncertain=stage==='INSTALL';
 const label=stage==='PLATFORM'?'平台连通性检查':stage==='DOWNLOAD'?'Agent 下载':'安装准备';
 if(['PLATFORM','DOWNLOAD'].includes(stage)){
  if(code===22){const status=/error:\s*(\d{3})/i.exec(text)?.[1];return {uncertain:false,detail:status==='404'?'平台接口返回 404：请使用安全平台的部署入口并保留子路径，确认部署前缀下的 /api 已转发到管理端；被管理主机或站点域名不能代替平台地址':status==='401'||status==='403'?'平台拒绝访问：请核对安装授权、代理认证及接口访问策略':label+'的 HTTP 请求失败，请检查平台地址和 API 路由'};}
  if(code===60)return {uncertain:false,detail:'平台 HTTPS 证书验证失败，请配置正确的受信 CA 或证书链，不能跳过验证'};
  if(code===6)return {uncertain:false,detail:'目标主机无法解析平台域名，请检查 DNS 和平台地址'};
  if(code===7||code===28)return {uncertain:false,detail:'目标主机无法连接平台或请求超时，请检查平台地址、端口与网络策略'};
  if(code===35)return {uncertain:false,detail:'平台 TLS 握手失败，请确认该地址提供 HTTPS 服务'};
 }
 if(stage==='PLATFORM')return {uncertain:false,detail:'该地址未返回安全平台就绪信息，请确认 /api/health/ready 返回 ready=true'};
 if(stage==='VERIFY')return {uncertain:false,detail:'下载程序的摘要校验失败，未执行安装，请核对发行制品及中间代理'};
 return {uncertain,detail:stage==='INSTALL'?'安装程序已启动但未确认完成，请核对接入任务、目标服务及受保护诊断；未自动重试':'远程安装前提检查失败，未执行安装，请检查 bash、curl、sha256sum 和目标权限'};
}
