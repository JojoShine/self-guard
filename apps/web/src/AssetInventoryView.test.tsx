import {it,expect} from 'vitest';import {renderToStaticMarkup} from 'react-dom/server';import {AssetInventoryView} from './AssetInventoryView';
it('shows actual application versions and provenance without exposing hidden inventory',()=>{
 const html=renderToStaticMarkup(<AssetInventoryView inventory={{components:[{ecosystem:'Go',name:'stdlib',version:'1.27.3',path:'/opt/app',provenance:'INSTALLED_METADATA',sourceSha256:'a'.repeat(64)},{ecosystem:'npm',name:'sample',version:'1.0.0',path:'/srv/bom.json',provenance:'SBOM'}],componentCollection:{complete:false,inputs:[{format:'GO_BINARY',path:'/opt/app',complete:false,reason:'开发模块缺少版本'}]}}}/>);
 for(const text of ['stdlib','1.27.3','实际部署元数据','SBOM（候选）','开发模块缺少版本','查看软件或版本依据'])expect(html).toContain(text);expect(renderToStaticMarkup(<AssetInventoryView inventory="[已隐藏]"/>)).toContain('[已隐藏]');
});
