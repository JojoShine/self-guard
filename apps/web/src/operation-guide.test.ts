/// <reference types="vite/client" />
import {describe,it,expect} from 'vitest';
import source from './main.tsx?raw';
import guide from './content/operation-guide.md?raw';

const menu=source.split('const groups:')[1].split('const names')[0];
const modules=[['overview','工作台'],...[...menu.matchAll(/\["([^"]+)",\s*"([^"]+)"\]/g)].map(match=>[match[1],match[2]])];

describe('Markdown operation guide coverage',()=>{
 it('documents every current menu without duplicate or missing module destinations',()=>{
  const entries=[...guide.matchAll(/\[前往([^\]]+)\]\(#([a-z-]+)\)/g)].map(match=>[match[2],match[1]]);
  expect(entries.sort()).toEqual(modules.slice().sort());
 });
 it('keeps each module explanation complete rather than an empty heading or destination list',()=>{
  for(const [,title] of modules){
   const content=guide.split('### '+title+'\n\n')[1]?.split(/\n#{2,3} /)[0];
   expect(content,title).toBeTruthy();
   expect(content.split('\n\n').filter(paragraph=>paragraph&&!paragraph.startsWith('[前往')).length,title).toBeGreaterThanOrEqual(3);
  }
 });
 it('provides valid configuration and import examples without executable changes',()=>{
  const examples=[...guide.matchAll(/```json\n([\s\S]*?)\n```/g)].map(match=>JSON.parse(match[1]));
  expect(examples.find(example=>example.mode)).toEqual({path:'/srv/app/config/app.conf',mode:'0640'});
  expect(examples.find(example=>example.items)?.items[0]).toMatchObject({externalId:'scanner-001',kind:'RISK',severity:'HIGH',source:'external-scanner'});
 });
 it('keeps all three workflows and their links within existing modules',()=>{
  for(const title of ['首次接入与检测','从风险到修复闭环','站点接入到安全阻断'])expect(guide).toContain('### '+title);
  for(const match of guide.matchAll(/\]\(#([^\)]+)\)/g))expect(modules.some(([key])=>key===match[1])).toBe(true);
 });
});
