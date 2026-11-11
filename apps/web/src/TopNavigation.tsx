import {useEffect,useRef} from 'react';import type {ReactNode} from 'react';
import {Brand} from './Brand';import {groups,resolveNavigation} from './navigation';
export function TopNavigation({page,onNavigate,children}:{page:string;onNavigate:(page:string)=>void;children?:ReactNode}){
 const {group,modules,activePage}=resolveNavigation(page),navigation=useRef<HTMLElement>(null);
 useEffect(()=>{for(const current of Array.from(navigation.current?.querySelectorAll<HTMLElement>('[aria-current="page"]')||[]))current.scrollIntoView({block:'nearest',inline:'nearest'})},[page]);
 return <header className="app-navigation" ref={navigation}>
  <div className="app-navigation-main"><button type="button" className="app-brand" aria-label="Self Guard 返回概览" onClick={()=>onNavigate('overview')}><Brand light/></button>
   <nav className="primary-navigation" aria-label="业务中心"><button type="button" aria-current={group?.[0]==='概览'?'page':undefined} onClick={()=>onNavigate('overview')}>概览</button>{groups.filter(([name])=>name!=='设置').map(([name,pages])=><button type="button" key={name} aria-current={group?.[0]===name?'page':undefined} onClick={()=>{if(group?.[0]!==name)onNavigate(pages[0][0])}}>{name}</button>)}</nav>
   <div className="app-navigation-actions"><button type="button" className="settings-entry" aria-label="设置" aria-current={group?.[0]==='设置'?'page':undefined} onClick={()=>onNavigate('operations')}>设置</button>{children}</div>
  </div>
  {group&&modules.length>0&&<div className="module-navigation-row"><nav className="module-navigation" aria-label={group[0]+'模块'}>{modules.map(([key,label])=><button type="button" key={key} aria-current={activePage===key?'page':undefined} onClick={()=>onNavigate(key)}>{label}</button>)}</nav></div>}
 </header>;
}
