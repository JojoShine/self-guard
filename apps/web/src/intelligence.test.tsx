import {it,expect,vi} from 'vitest';vi.mock('./api',()=>({api:vi.fn()}));
import {renderToStaticMarkup} from 'react-dom/server';import {IntelligenceRecordContent} from './IntelligencePanel';
it('shows actual applicability, unknown rating and purpose without elevating a candidate to a confirmed risk',()=>{
 const html=renderToStaticMarkup(<IntelligenceRecordContent record={{summary:'真实软件通告',purpose:'CANDIDATE',aliases:['CVE-2021-44228'],severity:null,details:'<script>not executable</script>',affected:[{fixed:'2.17.1',package:'log4j-core'}],scores:[],metadata:{knownExploited:true}}}/>);
 for(const value of ['真实软件通告','产品适用线索','未评级（来源未提供）','CVE-2021-44228','2.17.1','log4j-core','软件与版本适用条件'])expect(html).toContain(value);expect(html).not.toContain('<script>');expect(html).toContain('&lt;script&gt;');
});
