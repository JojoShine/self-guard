import {it,expect} from 'vitest';import {renderToStaticMarkup} from 'react-dom/server';import {HostPortInventory} from './HostPortInventory';
it('shows process evidence on nonstandard ports and marks port-only hints as unconfirmed',()=>{
 const html=renderToStaticMarkup(<HostPortInventory inventory={{ports:[{protocol:'tcp',address:'0.0.0.0',port:3306,software:'Nginx',identification:'PROCESS_SOCKET',processes:[{pid:42,name:'nginx'}]},{protocol:'tcp',address:'0.0.0.0',port:6379}]}}/>);
 for(const text of ['Nginx','nginx','42','进程关联','Redis','常见用途','未识别'])expect(html).toContain(text);
});
it('keeps withheld inventories hidden',()=>{expect(renderToStaticMarkup(<HostPortInventory inventory="[已隐藏]"/>)).toContain('当前权限不能读取端口清单')});
