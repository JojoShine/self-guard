import {it,expect} from 'vitest';
import {renderToStaticMarkup} from 'react-dom/server';
import {WafAccessView} from './WafAccessView';

it('shows actual access fields including zero duration without inventing request content',()=>{
 const html=renderToStaticMarkup(<WafAccessView record={{method:'GET',status:200,path:'[redacted]',nodeId:'owned-edge',siteId:'owned-site',durationMicros:0,timestamp:'2026-11-01T00:00:00Z'}}/>);
 for(const text of ['HTTP 200','路径已脱敏','owned-edge','owned-site','0 ms','不还原未保存'])expect(html).toContain(text);
 expect(html).not.toContain('暂无证据');
 expect(renderToStaticMarkup(<WafAccessView record={{}}/>)).toContain('未留存');
});
