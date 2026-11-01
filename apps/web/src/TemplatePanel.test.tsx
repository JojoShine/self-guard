import {describe,it,expect,vi} from 'vitest';
import React from 'react';
import {renderToStaticMarkup} from 'react-dom/server';
vi.stubGlobal('sessionStorage',{getItem:()=>null,setItem:vi.fn(),removeItem:vi.fn()});
const {TemplateDetails}=await import('./TemplatePanel');
describe('repair template details',()=>{
 it('shows immutable template parameters, preconditions, execution, fresh verification and recovery',()=>{
  const html=renderToStaticMarkup(<TemplateDetails template={{id:'FILE_PERMISSION',name:'权限修复',version:'1',enabled:true,impact:'受控权限修改',parameters:[{name:'path',required:true,description:'允许范围内的路径'},{name:'healthService',required:false,description:'允许的相关服务'}],preconditions:['路径必须通过本地检查'],steps:['记录原始权限','设置批准权限'],verification:['独立重新读取目标'],restore:['批准回滚后恢复原值']}}/>);
  for(const value of ['前置检查','执行步骤','独立验证','恢复步骤','path','healthService','必填','可选','路径必须通过本地检查','独立重新读取目标','批准回滚后恢复原值'])expect(html).toContain(value);
  expect(html).not.toContain('<input');
 });
});
