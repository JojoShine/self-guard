import {createContext,useCallback,useContext,useEffect,useId,useLayoutEffect,useRef,useState} from 'react';
import type {ReactNode} from 'react';import {createPortal} from 'react-dom';import {Breadcrumb,Button,Drawer} from 'antd';import type {DrawerProps} from 'antd';import {ArrowLeftOutlined} from '@ant-design/icons';
type Entry={id:string;parentId:string|null;title:ReactNode;canClose:boolean;close:()=>void};
type Workspace={target:HTMLDivElement|null;activeId:string|undefined;register:(entry:Entry)=>void;unregister:(id:string)=>void};
const Context=createContext<Workspace|null>(null),ParentContext=createContext<string|null>(null);
const layoutEffect=typeof window==='undefined'?useEffect:useLayoutEffect;
export function registerDetail(entries:Entry[],entry:Entry){const existing=entries.findIndex(row=>row.id===entry.id);if(existing>=0){if(entries[existing].title===entry.title&&entries[existing].canClose===entry.canClose)return entries;return entries.map(row=>row.id===entry.id?entry:row)}const child=entries.findIndex(row=>row.parentId===entry.id);return child<0?[...entries,entry]:[...entries.slice(0,child),entry,...entries.slice(child)];}
export function closeDetailLevels(entries:Entry[],index:number){const closing=entries.slice(index+1);if(closing.some(entry=>!entry.canClose))return false;for(const entry of [...closing].reverse())entry.close();return true;}
export function useDetailWorkspace(){return useContext(Context)!==null;}
export function DetailWorkspace({title,children}:{title:string;children:ReactNode}){
 const[entries,setEntries]=useState<Entry[]>([]),[target,setTarget]=useState<HTMLDivElement|null>(null);
 const register=useCallback((entry:Entry)=>setEntries(previous=>registerDetail(previous,entry)),[]),unregister=useCallback((id:string)=>setEntries(previous=>previous.filter(entry=>entry.id!==id)),[]);
 function backTo(index:number){closeDetailLevels(entries,index)}
 return <Context.Provider value={{target,activeId:entries.at(-1)?.id,register,unregister}}><div className="detail-workspace">
  <div className="workspace-page" hidden={entries.length>0}>{children}</div>
  {entries.length>0&&<nav className="detail-breadcrumb" aria-label="详情层级"><Breadcrumb items={[{title:<Button type="text" disabled={entries.some(entry=>!entry.canClose)} onClick={()=>backTo(-1)}>返回{title}</Button>},...entries.map((entry,index)=>({title:index===entries.length-1?<span aria-current="page">{entry.title}</span>:<Button type="text" disabled={entries.slice(index+1).some(child=>!child.canClose)} onClick={()=>backTo(index)}>{entry.title}</Button>}))]}/></nav>}
  <div className="workspace-details" ref={setTarget}/>
 </div></Context.Provider>;
}
export type DetailPanelProps=Omit<DrawerProps,'onClose'>&{onClose?:()=>void};
export function DetailPanel(props:DetailPanelProps){
 const workspace=useContext(Context),parentId=useContext(ParentContext),id=useId(),heading=useRef<HTMLHeadingElement>(null),current=useRef(props),returnTo=useRef<{element:HTMLElement|null;x:number;y:number}>(),visited=useRef(false);current.current=props;
 const close=useCallback(()=>current.current.onClose?.(),[]),canClose=props.closable!==false;
 const register=workspace?.register,unregister=workspace?.unregister,target=workspace?.target;
 layoutEffect(()=>{if(!props.open||!target||!register)return;register({id,parentId,title:props.title,canClose,close})},[props.open,target,register,id,parentId,props.title,canClose,close]);
 layoutEffect(()=>{if(!props.open||!target||!unregister)return;returnTo.current={element:document.activeElement instanceof HTMLElement?document.activeElement:null,x:window.scrollX,y:window.scrollY};return()=>{unregister(id);visited.current=false;const destination=returnTo.current;requestAnimationFrame(()=>{if(destination?.element?.isConnected){window.scrollTo(destination.x,destination.y);destination.element.focus({preventScroll:true})}})}},[props.open,target,unregister,id]);
 useEffect(()=>{if(!props.open||workspace?.activeId!==id||visited.current)return;visited.current=true;const frame=requestAnimationFrame(()=>{window.scrollTo(0,0);heading.current?.focus({preventScroll:true})});return()=>cancelAnimationFrame(frame)},[props.open,workspace?.activeId,id]);
 if(!workspace)return <Drawer {...props} onClose={close}/>;
 if(!props.open||!target)return null;
 return createPortal(<ParentContext.Provider value={id}><section className={'detail-page record-drawer '+(props.className||'')} hidden={workspace.activeId!==id} aria-labelledby={id+'-title'}>
  <header className="detail-page-header"><div className="detail-page-title"><Button icon={<ArrowLeftOutlined/>} disabled={!canClose} onClick={close}>返回上一级</Button><h1 ref={heading} tabIndex={-1} id={id+'-title'}>{props.title}</h1></div>{props.extra&&<div className="detail-page-extra">{props.extra}</div>}</header>
  <div className="detail-page-body">{props.children}</div>
 </section></ParentContext.Provider>,target);
}
