import type {ReactNode} from 'react';
import {Button,Drawer,Space} from 'antd';
import type {ModalProps} from 'antd';

export type FormDrawerProps=Pick<ModalProps,'children'|'title'|'open'|'keyboard'|'className'|'maskClosable'|'closable'|'cancelButtonProps'|'cancelText'|'okText'|'okButtonProps'|'onOk'|'confirmLoading'|'destroyOnClose'>&{width?:number|string;footer?:ReactNode;onCancel?:()=>void};

export function FormDrawer({children,title,open,width=560,className,keyboard,maskClosable,closable,confirmLoading=false,destroyOnClose,footer,cancelButtonProps,cancelText='取消',okButtonProps,okText='保存',onCancel,onOk}:FormDrawerProps){
 const canClose=!confirmLoading&&closable!==false;
 return <Drawer rootClassName="form-drawer-root" open={open} placement="right" push={false} width={width} title={title} className={['form-drawer',className].filter(Boolean).join(' ')} closable={canClose} maskClosable={canClose&&maskClosable!==false} keyboard={canClose&&keyboard!==false} destroyOnClose={destroyOnClose} onClose={()=>{if(canClose)onCancel?.()}} footer={footer===undefined?<Space className="form-drawer-actions" size={12} wrap><Button {...cancelButtonProps} disabled={confirmLoading||cancelButtonProps?.disabled} onClick={onCancel}>{cancelText}</Button><Button type="primary" {...okButtonProps} loading={confirmLoading} onClick={onOk}>{okText}</Button></Space>:footer}>{children}</Drawer>;
}
