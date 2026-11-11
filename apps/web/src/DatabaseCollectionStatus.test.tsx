import {it,expect,vi} from 'vitest';
vi.mock('./api',()=>({api:vi.fn()}));
import {renderToStaticMarkup} from 'react-dom/server';
import {DatabaseCollectionEvidenceView} from './DatabaseCollectionStatus';
it('keeps configured sources, host reports and collected events distinct',()=>{
 const base={checkedAt:'2026-11-09T00:00:00Z',windowMinutes:60,sources:0,hosts:{authorized:1,reporting:0},recentEvents:0,latestEventAt:null};
 expect(renderToStaticMarkup(<DatabaseCollectionEvidenceView value={base}/>)).toContain('未配置日志来源');
 expect(renderToStaticMarkup(<DatabaseCollectionEvidenceView value={{...base,sources:1}}/>)).toContain('等待采集主机上报');
 expect(renderToStaticMarkup(<DatabaseCollectionEvidenceView value={{...base,sources:1,hosts:{authorized:1,reporting:1}}}/>)).toContain('等待日志入库');
 const html=renderToStaticMarkup(<DatabaseCollectionEvidenceView value={{...base,sources:1,hosts:{authorized:1,reporting:1},recentEvents:3,latestEventAt:base.checkedAt}}/>);
 expect(html).toContain('近期收到审计记录');expect(html).toContain('不代表完整覆盖');expect(html).not.toContain('接入成功');
});
