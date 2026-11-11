import {it,expect,vi} from 'vitest';
import type {DrawerProps} from 'antd';
import {renderToStaticMarkup} from 'react-dom/server';
vi.mock('antd',async importOriginal=>{const actual=await importOriginal<typeof import('antd')>();return {...actual,Drawer:({open,title,children,closable,maskClosable,keyboard,placement,footer}:DrawerProps)=>open?<div role="dialog" data-placement={placement} data-closable={String(closable)} data-mask-closable={String(maskClosable)} data-keyboard={String(keyboard)}><h2>{title}</h2>{children}<footer>{footer}</footer></div>:null}});
import {ModuleSection} from './ModuleSection';
import {DetailWorkspace} from './DetailWorkspace';
import {RecordFormHost} from './RecordFormHost';
vi.mock('./api',()=>({api:vi.fn()}));
import {BusinessGroupCreateButton} from './BusinessGroupCreateButton';
it('form sections use a dialog without replacing the underlying detail workspace',()=>{const html=renderToStaticMarkup(<DetailWorkspace title="数据实例"><p>列表筛选仍在</p><ModuleSection modal title="添加实例" onClose={()=>{}}><input aria-label="实例名称"/></ModuleSection></DetailWorkspace>);expect(html).toContain('role="dialog"');expect(html).toContain('data-placement="right"');expect(html).toContain('实例名称');expect(html).toContain('列表筛选仍在');expect(html).not.toContain('返回上一级');});
it('busy form dialogs block close, backdrop and keyboard dismissal',()=>{const html=renderToStaticMarkup(<ModuleSection modal busy title="提交中" onClose={()=>{}}><p>提交内容</p></ModuleSection>);for(const key of ['closable','mask-closable','keyboard'])expect(html).toContain('data-'+key+'="false"');});
it('generic add forms use the right drawer host',()=>{const html=renderToStaticMarkup(<DetailWorkspace title="主机"><RecordFormHost open title="添加主机资产" onCancel={()=>{}}><input aria-label="主机名"/></RecordFormHost></DetailWorkspace>);expect(html).toContain('role="dialog"');expect(html).toContain('data-placement="right"');expect(html).toContain('主机名');});

it('drawer footer keeps save and cancel controls and disables cancellation during submission',()=>{const html=renderToStaticMarkup(<RecordFormHost open confirmLoading title="保存资产" okText="保存" cancelText="取消" onCancel={()=>{}} onOk={()=>{}}><p>表单</p></RecordFormHost>);expect(html).toContain('<footer>');expect(html).toMatch(/保\s*存<\/span>/);expect(html).toMatch(/<button[^>]*disabled[^>]*><span>取\s*消<\/span>/);for(const key of ['closable','mask-closable','keyboard'])expect(html).toContain('data-'+key+'="false"');});

it('business groups have a dedicated create button',()=>{expect(renderToStaticMarkup(<BusinessGroupCreateButton onCreated={()=>{}}/>)).toContain('新建业务分组');});
