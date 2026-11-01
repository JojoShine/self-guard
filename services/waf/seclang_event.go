package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/url"
)

func builtinPolicyDigest(config Policy) string {
	type pattern struct {
		ID         string `json:"id"`
		Expression string `json:"expression"`
	}
	definitions := make([]pattern, 0, len(patterns))
	for _, entry := range patterns {
		definitions = append(definitions, pattern{entry.id, entry.r.String()})
	}
	raw, _ := json.Marshal(struct {
		Version string
		Rules   []pattern
		Config  Policy
	}{"selfguard-builtin-v1", definitions, config})
	return fmt.Sprintf("%x", sha256.Sum256(raw))
}

func secBuiltinInspection(node string, site runtimeSite, rule, variable, value string) *secEventInspection {
	messages := map[string]string{"SQLI": "输入命中SQL查询组合或延时执行特征，需核对是否符合业务预期", "XSS": "输入命中脚本、事件处理器或脚本协议特征，存在跨站脚本风险", "TRAVERSAL": "输入命中向上级目录访问特征，需核对是否存在非授权文件访问", "COMMAND": "输入命中系统命令组合或命令替换特征，需核对命令注入风险", "IP": "客户端来源命中访问控制条件", "METHOD": "请求方法不在站点允许范围内", "PATH": "请求路径命中站点禁止访问条件", "RATE": "该来源请求超过站点或路径配置的频率限额", "ENCODING": "请求使用当前不支持的正文编码，无法完成正文内容检查"}
	message := messages[rule]
	if message == "" {
		message = "请求命中当前站点基础防护条件"
	}
	if len(variable) > 256 {
		variable = variable[:256]
	}
	u, _ := url.Parse(site.Upstream)
	return &secEventInspection{NodeID: node, SiteVersion: site.Version, BundleID: "selfguard-builtin-v1", BundleSHA256: site.builtinSHA256, SiteHostname: site.Hostname, ConfiguredUpstreamOrigin: u.Scheme + "://" + u.Host, DecisionStatus: 403, Complete: true, Matches: []string{rule}, Evidence: []secMatchEvidence{{RuleID: rule, Variable: variable, ValueSHA256: fmt.Sprintf("%x", sha256.Sum256([]byte(value))), ValueBytes: len(value), MessageTemplate: message}}}
}

type secEventInspection struct {
	NodeID                   string             `json:"nodeId"`
	SiteVersion              int                `json:"siteVersion"`
	BundleID                 string             `json:"bundleId"`
	BundleSHA256             string             `json:"bundleSha256"`
	SiteHostname             string             `json:"siteHostname"`
	ConfiguredUpstreamOrigin string             `json:"configuredUpstreamOrigin"`
	Score                    int                `json:"score"`
	DecisionStatus           int                `json:"decisionStatus"`
	Complete                 bool               `json:"complete"`
	FailureKind              string             `json:"failureKind,omitempty"`
	Matches                  []string           `json:"matches"`
	Evidence                 []secMatchEvidence `json:"evidence"`
	OmittedEvidence          int                `json:"omittedEvidence"`
}

func secInspectionEvent(node string, site runtimeSite, decision secResult, failure error) *secEventInspection {
	u, _ := url.Parse(site.Upstream)
	proof := &secEventInspection{NodeID: node, SiteVersion: site.Version, BundleID: site.rulePolicy.bundleID, BundleSHA256: site.rulePolicy.bundleSHA256, SiteHostname: site.Hostname, ConfiguredUpstreamOrigin: u.Scheme + "://" + u.Host, Score: decision.Score, DecisionStatus: decision.Status, Complete: failure == nil, Matches: append([]string{}, decision.Matches...), Evidence: append([]secMatchEvidence{}, decision.Evidence...), OmittedEvidence: decision.OmittedEvidence}
	if len(proof.Matches) > 32 {
		proof.Matches = proof.Matches[:32]
	}
	if len(proof.Evidence) > 8 {
		proof.OmittedEvidence += len(proof.Evidence) - 8
		proof.Evidence = proof.Evidence[:8]
	}
	if failure != nil {
		proof.FailureKind = secFailureKind(failure)
		proof.DecisionStatus = 503
	}
	return proof
}

func (e *engine) enqueueEvent(event Event) {
	if e.outbox != nil {
		if err := e.outbox.append(event); err != nil {
			e.dropped.Add(1)
		}
		return
	}
	select {
	case e.events <- event:
	default:
		e.dropped.Add(1)
	}
}
