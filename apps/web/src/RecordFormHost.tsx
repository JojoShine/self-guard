import {useEffect,useId,useRef} from 'react';
import {createPortal} from 'react-dom';
import {Button,Modal,Space,Typography} from 'antd';
import type {ModalProps} from 'antd';

type Props=Pick<ModalProps,'children'|'className'|'title'|'open'|'centered'|'maskClosable'|'closable'|'cancelButtonProps'|'cancelText'|'okText'|'okButtonProps'|'onCancel'|'onOk'|'confirmLoading'|'destroyOnClose'>&{inlineTarget?:HTMLElement|null};

export function RecordFormHost({inlineTarget,...props}:Props){
 const titleId=useId(),editor=useRef<HTMLElement>(null);
 useEffect(()=>{if(props.open&&inlineTarget){editor.current?.scrollIntoView({block:'nearest'});editor.current?.focus({preventScroll:true})}},[props.open,inlineTarget,props.title]);
 if(!inlineTarget)return <Modal {...props}/>;
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
