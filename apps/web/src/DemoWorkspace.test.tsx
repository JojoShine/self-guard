import {expect,it,vi} from 'vitest';
import {renderToStaticMarkup} from 'react-dom/server';
vi.mock('./api',()=>({api:vi.fn()}));
import {DemoWorkspaceContent,DemoSqlResult,type DemoState} from './DemoWorkspace';
const state:DemoState={revision:1,expiresAt:Date.now()+3600000,assets:[{id:'old',name:'旧版样例主机',profile:'OUTDATED'}],scans:[{id:'scan',name:'版本检查',assetIds:['old'],status:'READY',findingIds:[]}],findings:[{id:'issue',scanId:'scan',assetId:'old',title:'样例版本过旧',summary:'仅供体验',status:'OPEN'}],sqlSamples:[{id:'sql',label:'合成 SQL',statements:[{sql:'SELECT synthetic_secret',stage:'QUERY'}],state:'EXTRACTED',reasons:[]}]};
function render(overrides:Partial<Parameters<typeof DemoWorkspaceContent>[0]>={}){return renderToStaticMarkup(<DemoWorkspaceContent state={state} busy={false} error="" onRefresh={()=>{}} onAction={async()=>true} onLogout={async()=>{}} {...overrides}/>)}
it('offers persistent sample workflows with explicit safety boundaries',()=>{
 const html=render();
 for(const text of ['非生产','会话独立','8 小时','不访问目标','添加样例资产','创建检查任务','执行样例检查','问题处置','SQL 样例解析','重置本空间','旧版样例主机','样例版本过旧'])expect(html).toContain(text);
 expect(html).not.toContain('SELECT synthetic_secret');
});
it('keeps server failures visible and offers refresh without displaying stale workspace',()=>{
 const html=render({state:undefined,error:'版本冲突，请刷新后重试'});
 expect(html).toContain('版本冲突，请刷新后重试');expect(html).toContain('刷新空间');expect(html).not.toContain('旧版样例主机');
});
it('disables writes while waiting for the server',()=>{
 const html=render({busy:true});expect(html).toMatch(/disabled=""[^>]*><span>执/);expect(html).toContain('aria-busy="true"');
});

it('explains SQL extraction state in Chinese while keeping payload hidden by default',()=>{
 const html=render();expect(html).toContain('已提取 SQL');expect(html).not.toContain('EXTRACTED');
});
it('shows Chinese statement stages and known parser limitations in sample details',()=>{
 const html=renderToStaticMarkup(<DemoSqlResult result={{id:'prepared',label:'合成样例',state:'PARTIAL',reasons:['TLS_NO_PLAINTEXT','PREPARED_CONTEXT_MISSING'],statements:[{sql:'SELECT $1',stage:'PREPARE'},{sql:'SELECT $1',stage:'EXECUTE'}]}}/>);
 for(const text of ['准备语句','执行请求','流量已加密','缺少准备语句上下文','SELECT $1'])expect(html).toContain(text);
 for(const code of ['TLS_NO_PLAINTEXT','PREPARED_CONTEXT_MISSING','EXECUTE'])expect(html).not.toContain(code);
});
