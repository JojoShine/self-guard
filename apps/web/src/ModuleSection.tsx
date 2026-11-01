import type {ReactNode} from 'react';
import {Alert,Drawer,Tag,Typography} from 'antd';
import {displayStatus,displaySeverity,severityTone,statusTone} from './presentation';

export function ModuleSection({title,description,extra,children,flush=false,onClose,busy=false,error}:{title:string;description?:ReactNode;extra?:ReactNode;children:ReactNode;flush?:boolean;onClose?:()=>void;busy?:boolean;error?:string}){
 if(onClose)return <Drawer open placement="right" title={title} extra={extra} className="record-drawer module-drawer" width="min(960px, calc(100vw - 24px))" closable={!busy} maskClosable={!busy} onClose={()=>{if(!busy)onClose()}}><div className="module-stack">{description&&<Typography.Paragraph type="secondary">{description}</Typography.Paragraph>}{error&&<Alert type="error" showIcon message={error}/>}<div className="module-stack">{children}</div></div></Drawer>;
 return <section className="module-section" aria-label={title}><header className="module-section-header"><div><h2>{title}</h2>{description&&<p>{description}</p>}</div>{extra&&<div className="module-section-extra">{extra}</div>}</header><div className={'module-section-body'+(flush?' module-section-body--flush':'')}>{children}</div></section>;
}
export function ModuleToolbar({children}:{children:ReactNode}){return <div className="module-toolbar">{children}</div>;}
export function StatusTag({value,labels,label,icon,ariaLabel,tone}:{value:unknown;labels?:Record<string,string>;label?:string;icon?:ReactNode;ariaLabel?:string;tone?:ReturnType<typeof statusTone>}){
 const key=String(value??'');
 return <Tag className="sg-status-tag" color={tone||statusTone(value)} icon={icon??<span className="status-tag-dot" aria-hidden="true"/>} aria-label={ariaLabel}>{label??(labels&&Object.hasOwn(labels,key)?labels[key]:displayStatus(value))}</Tag>;
}
export function SeverityTag({value,ariaLabel}:{value:unknown;ariaLabel?:string}){return <Tag className="sg-severity-tag" color={severityTone(value)} aria-label={ariaLabel}>{displaySeverity(value)}</Tag>;}
export function DetectionMatchTag({matched,status}:{matched:unknown;status:unknown}){if(matched===true)return <StatusTag value="MATCHED"/>;if(matched===false&&status==='COMPLETED')return <StatusTag value="NO_MATCH"/>;return null;}
