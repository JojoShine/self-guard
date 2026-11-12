import {expect,it,vi} from 'vitest';
import {renderToStaticMarkup} from 'react-dom/server';
vi.mock('./api',()=>({api:vi.fn()}));
import {onboardingPermission,DatabaseOnboardingResult,DatabaseOnboardingScope} from './DatabaseOnboardingPanel';
it('requires a current successful check for every target and instance revision',()=>{
 expect(onboardingPermission('a','b','CHECKED')).toEqual({install:false,prepare:false});
 expect(onboardingPermission('a','a','CHECKED')).toEqual({install:true,prepare:false});
 expect(onboardingPermission('a','a','WAITING_RESTART')).toEqual({install:false,prepare:true});
 expect(onboardingPermission('a','a','CHECKED',true)).toEqual({install:false,prepare:true});
 expect(onboardingPermission('a','a','BLOCKED')).toEqual({install:false,prepare:false});
});
it('explains restart maintenance without promising automatic restart or records',()=>{
 const html=renderToStaticMarkup(<DatabaseOnboardingResult state="WAITING_RESTART"/>);
 expect(html).toContain('等待维护窗口');expect(html).toContain('不会重启数据库');expect(html).toContain('不立即开启SQL记录');
 const blocked=renderToStaticMarkup(<DatabaseOnboardingResult state="BLOCKED"/>);expect(blocked).toContain('不可启用');
});
it('does not treat installation as actual SQL arrival',()=>{
 expect(renderToStaticMarkup(<DatabaseOnboardingResult state="INSTALLED"/>)).toContain('仍需验证真实数据');
});

it('explains service-wide PostgreSQL logging and FILE retention separately',()=>{
 for(const deployment of ['HOST','DOCKER'] as const){const html=renderToStaticMarkup(<DatabaseOnboardingScope deployment={deployment}/>);for(const text of ['整个PostgreSQL服务','全部数据库SQL','不是采集过滤','独立权限与7天期限'])expect(html).toContain(text)}
 const html=renderToStaticMarkup(<DatabaseOnboardingScope deployment="FILE"/>);expect(html).toContain('原始日志保留由原系统管理');expect(html).toContain('不负责删除原始日志');expect(html).not.toContain('全部数据库SQL');
});
