import {useMemo,useState} from 'react';
import {Segmented,Switch,Tag} from 'antd';
import './traffic-payload.css';

type Language='JSON'|'HTTP'|'TEXT'|'HEX';
type Payload={text:string;language:Language};

function prettyJSON(text:string):string|undefined{
 try{JSON.parse(text)}catch{return undefined}
 // Retain source tokens: parsing and serializing would round large numeric IDs.
 const tokens=text.match(/"(?:\\[\s\S]|[^"\\])*"|[{}\[\],:]|[^\s{}\[\],:]+/g)||[];
 let output='',depth=0;
 const newline=()=> '\n'+'  '.repeat(depth);
 for(let index=0;index<tokens.length;index++){
  const token=tokens[index];
  if(token==='{'||token==='['){
   output+=token;depth++;if(depth>64)return undefined;
   if(tokens[index+1]!=='}'&&tokens[index+1]!==']')output+=newline();
  }else if(token==='}'||token===']'){
   depth--;if(tokens[index-1]!=='{'&&tokens[index-1]!=='[')output+=newline();output+=token;
  }else if(token===',')output+=','+newline();
  else if(token===':')output+=': ';
  else output+=token;
  if(output.length>262144)return undefined;
 }
 return output;
}

export function formatTrafficPayload(text:string,mode:'TEXT'|'HEX'):Payload{
 if(mode==='HEX'){
  const bytes=text.trim().split(/\s+/).filter(Boolean),lines:string[]=[];
  for(let offset=0;offset<bytes.length;offset+=16){
   const row=bytes.slice(offset,offset+16),ascii=row.map(value=>{const byte=Number.parseInt(value,16);return byte>=32&&byte<=126?String.fromCharCode(byte):'.'}).join('');
   lines.push(offset.toString(16).padStart(8,'0')+'  '+row.join(' ').padEnd(47,' ')+'  |'+ascii+'|');
  }
  return {text:lines.join('\n'),language:'HEX'};
 }
 if(/^(?:HTTP\/\d(?:\.\d)?\s+\d{3}\b|[A-Z]+\s+\S+\s+HTTP\/\d(?:\.\d)?\b)/.test(text)){
  const normalized=text.replace(/\r\n/g,'\n'),boundary=normalized.indexOf('\n\n');
  if(boundary<0)return {text:normalized,language:'HTTP'};
  const body=normalized.slice(boundary+2);
  return {text:normalized.slice(0,boundary+2)+(prettyJSON(body)??body),language:'HTTP'};
 }
 const json=prettyJSON(text);
 return json===undefined?{text,language:'TEXT'}:{text:json,language:'JSON'};
}

function codeTokens(line:string,json:boolean){
 if(!json)return line;
 const pattern=/"(?:\\[\s\S]|[^"\\])*"|\b(?:true|false|null)\b|-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?|[{}\[\],:]/g;
 const parts=[],matches=line.matchAll(pattern);let end=0;
 for(const match of matches){
  const offset=match.index!,value=match[0];if(offset>end)parts.push(line.slice(end,offset));
  const kind=value.startsWith('"')?(/^\s*:/.test(line.slice(offset+value.length))?'key':'string'):/^(true|false|null)$/.test(value)?'literal':/^-?\d/.test(value)?'number':'punctuation';
  parts.push(<span className={'payload-token-'+kind} key={offset}>{value}</span>);end=offset+value.length;
 }
 if(end<line.length)parts.push(line.slice(end));return parts;
}

export function TrafficPayloadView({text,mode}:{text:string;mode:'TEXT'|'HEX'}){
 const [view,setView]=useState<string|number>('formatted'),[wrap,setWrap]=useState(false);
 const formatted=useMemo(()=>formatTrafficPayload(text,mode),[text,mode]);
 const shown=view==='raw'?text:formatted.text,lines=shown.split(/\r\n|\n|\r/),httpBoundary=formatted.language==='HTTP'?lines.indexOf(''):-1;
 return <section className={'payload-view'+(wrap?' payload-view--wrap':'')} aria-label="报文代码视图">
  <div className="payload-toolbar"><div className="payload-controls"><Tag>{formatted.language}</Tag><Segmented aria-label="报文展示方式" value={view} onChange={setView} options={[{label:'格式化',value:'formatted'},{label:'原文',value:'raw'}]}/></div><label className="payload-wrap"><Switch size="small" checked={wrap} onChange={setWrap} aria-label="自动换行"/>自动换行</label></div>
  <pre className="payload-code" tabIndex={0} aria-label="原始访问证据代码预览"><code>{lines.map((line,index)=>{
   const httpHeader=formatted.language==='HTTP'&&(httpBoundary<0||index<httpBoundary);
   return <span className="payload-code-line" key={index}><span className="payload-line-number" aria-hidden="true">{index+1}</span><span className={'payload-line-content'+(httpHeader?' payload-http-header':'')}>{httpHeader&&index===0?<span className="payload-http-start">{line}</span>:codeTokens(line,formatted.language==='JSON'||(formatted.language==='HTTP'&&index>httpBoundary&&httpBoundary>=0))}{'\n'}</span></span>;
  })}</code></pre>
  <div className="payload-caption">格式化仅用于阅读，存储与下载保留原始字节。</div>
 </section>;
}
