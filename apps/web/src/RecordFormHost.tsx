import {DetailPanel,useDetailWorkspace} from './DetailWorkspace';
import {useEffect,useId,useRef} from 'react';
import {createPortal} from 'react-dom';
import {Button,Space,Typography} from 'antd';
import {FormDrawer} from './FormDrawer';
import type {FormDrawerProps} from './FormDrawer';

type Props=FormDrawerProps&{inlineTarget?:HTMLElement|null;fullPage?:boolean;onCancel?:()=>void};

export function RecordFormHost({inlineTarget,fullPage=false,...props}:Props){
 const titleId=useId(),editor=useRef<HTMLElement>(null),workspace=useDetailWorkspace();
 useEffect(()=>{if(props.open&&inlineTarget){editor.current?.scrollIntoView({block:'nearest'});editor.current?.focus({preventScroll:true})}},[props.open,inlineTarget,props.title]);
 if(fullPage&&workspace&&!inlineTarget)return <DetailPanel open={props.open} title={props.title} onClose={props.onCancel} closable={props.closable!==false&&!props.confirmLoading} className="record-form-page"><div className="record-form-page-content">{props.children}</div><Space className="record-form-inline-actions" wrap><Button type="primary" {...props.okButtonProps} loading={props.confirmLoading} onClick={props.onOk}>{props.okText}</Button><Button {...props.cancelButtonProps} onClick={props.onCancel}>{props.cancelText}</Button></Space></DetailPanel>;
 if(!inlineTarget)return <FormDrawer {...props}/>;
 if(!props.open)return null;
 return createPortal(<section ref={editor} className="record-inline-editor record-form-inline" tabIndex={-1} aria-labelledby={titleId}>
  <Typography.Title level={5} id={titleId}>{props.title}</Typography.Title>
  <div className="record-form-inline-body">{props.children}</div>
  <Space className="record-form-inline-actions" wrap size={8}>
   <Button type="primary" {...props.okButtonProps} aria-label={typeof props.okText==='string'?props.okText:undefined} loading={props.confirmLoading} onClick={props.onOk}>{props.okText}</Button>
   <Button {...props.cancelButtonProps} aria-label={typeof props.cancelText==='string'?props.cancelText:undefined} onClick={props.onCancel}>{props.cancelText}</Button>
  </Space>
 </section>,inlineTarget);
}
