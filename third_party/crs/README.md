# OWASP CRS 固定兼容输入

版本：v4.25.1（LTS），入站 PL1 为首个验收配置。
来源：https://github.com/coreruleset/coreruleset/releases/tag/v4.25.1
下载：https://codeload.github.com/coreruleset/coreruleset/tar.gz/refs/tags/v4.25.1
源包 SHA-256：`0539e66e7627fe71c160a644d8fb7ab6e450d53c9de208be5f95a35c70e1a154`。

原规则、数据文件和许可保留于版本目录。通过官方 HTTPS 下载并固定摘要；本记录不声称已经校验上游发布者 GPG 签名。作为候选输入供兼容检查使用，尚未接入生产或标记兼容通过。

引擎保持自研。所有活动语义必须通过实现和测试才能发布；不支持的语义不得静默忽略。


自研入站档位的正文变量契约采用处理器相关可见性：URLENCODED保留REQUEST_BODY；XML/JSON/MULTIPART使用解析集合；未识别类型通过头阶段force控制启用原文。错误解析保留原文和不完整状态。该契约须与所选CRS样本同时验收，不能据此声称与所有ModSecurity版本等价；[上游v3实现](https://github.com/owasp-modsecurity/ModSecurity/blob/v3/master/src/transaction.cc)对原文的可见性存在差异。

原始头保留重复项与空值。Apache对重复Content-Type的合并、对CL/TE的处理与本档位不同；固定语料920181/920620的原断言仍单独保留失败记录，不能通过删除告警来掩盖差异。当前完整回放还有日志/状态和不完整检查待验收；基础兼容检查通过不代表站点运行发布通过。
