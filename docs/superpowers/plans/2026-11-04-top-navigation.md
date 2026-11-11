# 顶部导航与详情页实施清单

规格：docs/superpowers/specs/2026-11-04-top-navigation-design.md。直接执行已说明的方案；不覆盖现有工作，不提交、不推送。

- [x] 1. 抽取现有导航数据至navigation.ts，先验证现有模块完整、策略分组/未知页面/工作台选择；TopNavigation.tsx使用已有品牌与账户操作，替换Sider和开合状态。
- [x] 2. DetailWorkspace.tsx复用portal模式管理详情注册/返回/隐藏列表/焦点；注册更新不改变详情栈顺序，父子初次同时挂载也保持父在前。DetailPanel复用DrawerProps并在无工作区时兼容原Drawer。
- [x] 3. ModuleSection和现有Drawer入口切换共享DetailPanel，保留业务内容、忙碌状态和原onClose；主RecordFormHost仅长表单转页面，短确认/密码仍保留Modal。
- [x] 4. 沿用设计变量实现顶部导航、模块条、详情面包屑和响应式；页面区域使用释放后的宽度。
- [x] 5. 定向/全量前端测试、生产构建，真实浏览器检查资产列表→详情→流量/管理连接→返回、数据库配置、策略分组和窄屏；发现交互问题先定位修复。
- [x] 6. 只部署Web，保留API/数据库/Agent运行与旧镜像；验证线上构建、菜单和详情交互，记录实际验收结果。

验收（2026-11-04）：146项前端测试、生产构建、diff检查通过；浏览器实际检查资产详情→编辑取消、软件依据→返回保持页内选择与焦点、流量子页→返回保持列表筛选、数据库详情→编辑→返回、风险→跨模块创建任务保留预填值、离开模块清理旧表单。窄屏390px详情实际宽351px/文档375px，无页面横向溢出；顶部三级策略导航当前项正确。只替换Web容器，线上HTML/JS与构建逐字节一致，两台主机持续监测仍RUNNING且上报新鲜。交付包SHA256：07c8ee77f14678dd297c9420874f4f176bcbdf585fb2c2e9204d2842a0e718d9。线上验收记录 .artifacts/results/waf-production-nginx/top-navigation-live-verified.json、服务端state/top-navigation-20261104-verified.json；桌面截图top-navigation-asset-desktop.png。
