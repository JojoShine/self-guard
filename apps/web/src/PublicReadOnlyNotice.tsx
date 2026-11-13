import {Alert} from 'antd';
export function PublicReadOnlyNotice(){
 return <Alert banner showIcon type="info" message="全功能浏览 · 只读账号" description="可查看全部菜单和已公开的数据，使用筛选、详情和刷新。部分真实资产及关联记录不对公开账号展示。不能新增、修改、删除或执行操作；密码、密钥、SQL 和请求响应等敏感原文隐藏。"/>;
}
