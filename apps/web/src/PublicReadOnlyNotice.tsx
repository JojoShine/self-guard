import {Alert} from 'antd';
export function PublicReadOnlyNotice(){
 return <Alert banner showIcon type="info" message="全功能浏览 · 只读账号" description="可查看全部菜单与平台现有数据，使用筛选、详情和刷新。不能新增、修改、删除或执行任何操作；密码、密钥、SQL 和请求响应等敏感原文隐藏。"/>;
}
