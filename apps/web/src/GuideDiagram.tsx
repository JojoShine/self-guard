import {useEffect,useId,useState} from 'react';

export function diagramTitle(source:string){return /^accTitle:\s*(.+)$/m.exec(source)?.[1]||'操作流程图';}
let renderer:Promise<typeof import('mermaid')['default']>|undefined;
function loadRenderer(){return renderer??=import('mermaid').then(({default:mermaid})=>{mermaid.initialize({startOnLoad:false,securityLevel:'strict',suppressErrorRendering:true,maxTextSize:20000,maxEdges:100,theme:'neutral',flowchart:{htmlLabels:false,useMaxWidth:true},fontFamily:'system-ui, sans-serif'});return mermaid});}
export function GuideDiagram({source}:{source:string}){
 const id='guide-diagram-'+useId().replace(/[^a-zA-Z0-9]/g,''),[svg,setSvg]=useState(''),[error,setError]=useState(false);
 useEffect(()=>{let active=true;setSvg('');setError(false);void loadRenderer().then(m=>m.render(id,source)).then(result=>{if(active)setSvg(result.svg)}).catch(()=>{if(active)setError(true)});return()=>{active=false}},[source,id]);
 return <figure className="guide-diagram" aria-label={diagramTitle(source)}><figcaption>{diagramTitle(source)}</figcaption>{svg?<div className="guide-diagram-image" role="img" aria-label={diagramTitle(source)} dangerouslySetInnerHTML={{__html:svg}}/>:<p role="status">{error?'流程图暂时无法显示，请查看下方流程文字。':'流程图加载中…'}</p>}<details><summary>查看流程文字</summary><pre>{source}</pre></details></figure>
}
