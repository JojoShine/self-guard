/// <reference types="vite/client" />
import {Button} from 'antd';
import {ArrowLeftOutlined,CaretRightOutlined} from '@ant-design/icons';
import {memo,useEffect,useRef,useState} from 'react';
import Markdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import {Brand} from './Brand';
import guide from './content/operation-guide.md?raw';
import './operation-guide.css';

type Heading={id:string;title:string;level:number};
const headings:Heading[]=guide.split('\n').flatMap((line,index)=>{
 const match=/^(#{2,3}) (.+)$/.exec(line);
 return match?[{id:'guide-heading-'+(index+1),title:match[2],level:match[1].length}]:[];
});
const chapters:(Heading&{children:Heading[]})[]=[];
for(const heading of headings){if(heading.level===2)chapters.push({...heading,children:[]});else chapters.at(-1)?.children.push(heading);}

const GuideMarkdown=memo(function GuideMarkdown(){
 return <Markdown skipHtml remarkPlugins={[remarkGfm]} components={{h2:({node,...props})=><h2 {...props} id={'guide-heading-'+node?.position?.start.line}/>,h3:({node,...props})=><h3 {...props} id={'guide-heading-'+node?.position?.start.line}/>,table:({node,...props})=><div className="guide-table-wrapper" role="group" aria-label="说明表格" tabIndex={0}><table {...props}/></div>,pre:({node,...props})=><pre {...props} role="group" aria-label="代码示例" tabIndex={0}/>}}>{guide}</Markdown>;
});

export function OperationGuide({onReturn}:{onReturn:()=>void}){
 const [active,setActive]=useState(headings[0].id),[expanded,setExpanded]=useState([chapters[0].id]);
 const toc=useRef<HTMLDivElement>(null);
 const navigationTarget=useRef<string|null>(null);
 const chapter=chapters.find(item=>item.id===active||item.children.some(child=>child.id===active))||chapters[0];
 useEffect(()=>{setExpanded(previous=>previous.includes(chapter.id)?previous:[...previous,chapter.id]);},[chapter.id]);
 useEffect(()=>{
  let frame=0;
  const update=()=>{
   frame=0;
   if(navigationTarget.current)return;
   let current=headings[0].id;
   if(window.scrollY>0&&window.scrollY+window.innerHeight>=document.documentElement.scrollHeight-2)current=headings.at(-1)!.id;
   else for(const heading of headings){const element=document.getElementById(heading.id);if(element&&element.getBoundingClientRect().top<=112)current=heading.id;else break;}
   setActive(current);
  };
  const scroll=()=>{if(!frame)frame=requestAnimationFrame(update);};
  const inDirectory=(event:Event)=>event.target instanceof Element&&!!event.target.closest('.guide-toc');
  const resumeReading=(event:Event)=>{
   if(inDirectory(event))return;
   if(event instanceof KeyboardEvent&&(!['ArrowUp','ArrowDown','PageUp','PageDown','Home','End',' '].includes(event.key)||(event.target instanceof Element&&event.target.closest('input,textarea,select,[contenteditable=true]'))))return;
   navigationTarget.current=null;scroll();
  };
  const pointerDown=(event:Event)=>{if(!inDirectory(event))navigationTarget.current=null;};
  window.addEventListener('scroll',scroll,{passive:true});
  window.addEventListener('resize',scroll);
  for(const event of ['wheel','touchmove','keydown'])window.addEventListener(event,resumeReading,{passive:true});
  window.addEventListener('pointerdown',pointerDown,{passive:true});
  update();
  return()=>{
   window.removeEventListener('scroll',scroll);window.removeEventListener('resize',scroll);
   for(const event of ['wheel','touchmove','keydown'])window.removeEventListener(event,resumeReading);
   window.removeEventListener('pointerdown',pointerDown);cancelAnimationFrame(frame);
  };
 },[]);
 useEffect(()=>{
  const container=toc.current,selected=container?.querySelector<HTMLElement>('[aria-current=location]');
  if(!container||!selected)return;
  const bounds=container.getBoundingClientRect(),item=selected.getBoundingClientRect();
  if(item.top<bounds.top)container.scrollTop-=bounds.top-item.top;
  else if(item.bottom>bounds.bottom)container.scrollTop+=item.bottom-bounds.bottom;
 },[active,expanded]);
 function jump(id:string){navigationTarget.current=id;setActive(id);document.getElementById(id)?.scrollIntoView({block:'start'});}
 return <main className="operation-guide-page">
  <header className="guide-document-header"><div className="guide-document-header-inner"><div className="guide-header-brand"><Brand/><span>使用文档</span></div><Button icon={<ArrowLeftOutlined/>} onClick={onReturn}>返回系统</Button></div></header>
  <div className="guide-document-layout">
   <nav className="guide-toc" aria-label="操作指南目录">
    <div className="guide-toc-header"><h2>文档目录</h2><p>按使用过程阅读，或定位具体功能</p></div>
    <div className="guide-toc-scroll" ref={toc}>{chapters.map(item=><div className="guide-toc-group" key={item.id}>
     <div className="guide-toc-group-heading">
      {!!item.children.length&&<Button type="text" className="guide-toc-toggle" aria-label={(expanded.includes(item.id)?'收起':'展开')+item.title+'目录'} aria-expanded={expanded.includes(item.id)} icon={<CaretRightOutlined rotate={expanded.includes(item.id)?90:0}/>} onClick={()=>setExpanded(previous=>previous.includes(item.id)?previous.filter(id=>id!==item.id):[...previous,item.id])}/>}
      <Button type="text" className="guide-toc-link guide-toc-chapter" aria-current={active===item.id?'location':undefined} onClick={()=>jump(item.id)}>{item.title}</Button>
     </div>
     <div className="guide-toc-children" hidden={!expanded.includes(item.id)}>{item.children.map(child=><Button key={child.id} type="text" className="guide-toc-link guide-toc-level-3" aria-current={active===child.id?'location':undefined} onClick={()=>jump(child.id)}>{child.title}</Button>)}</div>
    </div>)}</div>
   </nav>
   <article className="guide-markdown" aria-label="操作指南正文">
    <div className="guide-article-meta"><span>功能使用指南</span><span>理解功能 · 完成操作 · 判断结果</span></div>
    <GuideMarkdown/>
   </article>
  </div>
 </main>;
}
