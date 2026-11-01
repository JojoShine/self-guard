import {describe,it,expect} from 'vitest';
import {renderToStaticMarkup} from 'react-dom/server';
import {OperationGuide} from './OperationGuide';

describe('standalone Markdown operation guide',()=>{
 it('renders the complete document with semantic headings, steps and module links',()=>{
  const html=renderToStaticMarkup(<OperationGuide onReturn={()=>{}}/>);
  expect(html).toContain('<h1>Self Guard 操作指南</h1>');
  expect(html).toMatch(/<h2 id="guide-heading-\d+">理解系统中的安全对象<\/h2>/);
  expect(html).toMatch(/<h3 id="guide-heading-\d+">站点管理<\/h3>/);
  expect(html).toContain('业务流量必须实际经过 WAF');
  expect(html).toContain('href="#sites"');
  expect(html).toContain('<ol>');
  expect(html).toContain('预期当前状态');
  expect(html).toContain('<table>');
  expect(html).toContain('<blockquote>');
  expect(html).toContain('class="language-json"');
  expect(html).toMatch(/<h2 id="guide-heading-\d+">按现象排查问题<\/h2>/);
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
  expect(targets.length).toBeGreaterThan(42);
  expect(html).not.toContain('ant-select');
  expect(html).not.toContain('module-section');
  expect(html).not.toContain('ant-collapse');
 });
});
