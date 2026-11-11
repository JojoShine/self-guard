import {describe,it,expect} from 'vitest';
import {renderToStaticMarkup} from 'react-dom/server';
import {OperationGuide} from './OperationGuide';

describe('standalone Markdown operation guide',()=>{
 it('renders concise core task guidance without retired workflow instructions',()=>{
  const html=renderToStaticMarkup(<OperationGuide onReturn={()=>{}}/>);
  expect(html).toContain('<h1>Self Guard 使用指南</h1>');
  expect(html).toMatch(/<h2 id="guide-heading-\d+">开始使用<\/h2>/);
  expect(html).toMatch(/<h3 id="guide-heading-\d+">数据实例、分类与访问<\/h3>/);
  expect(html).toContain('正文从捕获时间起保留7天');
  expect(html).not.toContain('href="#sites"');expect(html).not.toContain('创建关联修复任务');
 });
 it('pairs every directory entry with a unique Markdown heading without the system sidebar',()=>{
  const html=renderToStaticMarkup(<OperationGuide onReturn={()=>{}}/>);
  expect(html).toContain('返回系统');
  expect(html).toContain('aria-label="操作指南正文"');
  expect(html).not.toContain('sidebar');
  expect(html).toContain('aria-label="操作指南目录"');
  expect(html).toContain('aria-expanded="true"');
  expect(html).toContain('aria-expanded="false"');
  expect(html).toContain('guide-toc-children');
  const targets=[...html.matchAll(/id="(guide-heading-\d+)"/g)].map(match=>match[1]);
  expect(new Set(targets).size).toBe(targets.length);
  expect(targets.length).toBe((html.match(/class="ant-btn[^"]*guide-toc-link/g)||[]).length);
  expect(targets.length).toBeGreaterThanOrEqual(8);expect(targets.length).toBeLessThan(24);
  expect(html).not.toContain('ant-select');
  expect(html).not.toContain('module-section');
  expect(html).not.toContain('ant-collapse');
 });
});
