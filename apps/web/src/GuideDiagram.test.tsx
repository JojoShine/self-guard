import {it,expect} from 'vitest';
import {renderToStaticMarkup} from 'react-dom/server';
import {GuideDiagram,diagramTitle} from './GuideDiagram';
it('keeps a readable, labelled diagram source while the local renderer loads',()=>{
 const source='flowchart TD\naccTitle: 服务器监控接入流程\nA[登记主机] --> B[安装采集器]';
 expect(diagramTitle(source)).toBe('服务器监控接入流程');
 const html=renderToStaticMarkup(<GuideDiagram source={source}/>);expect(html).toContain('服务器监控接入流程');expect(html).toContain('查看流程文字');expect(html).toContain('登记主机');expect(html).not.toContain('<script');
});
