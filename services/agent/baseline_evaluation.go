package main

import (
	"crypto/sha256"
	"fmt"
	"strings"
)

func observedConfigValue(body, key string) (string, int) {
	actual := ""
	count := 0
	for _, line := range strings.Split(body, "\n") {
		name, value, ok := strings.Cut(line, "=")
		if ok && name == key {
			actual = value
			count++
		}
	}
	return actual, count
}

// Both host collection and offline fixtures use this same compliance decision.
func baselineFinding(c Check, kind, actual, expected, status string) map[string]any {
	if status == "checked" && actual == expected {
		return nil
	}
	evidence := map[string]string{"path": c.Path, "type": kind, "service": c.Service, "key": c.Key, "status": status}
	if kind != "CONFIG_VALUE" {
		evidence["actual"] = actual
		evidence["expected"] = expected
	}
	f := event("baseline:"+kind+":"+c.Path+":"+c.Service+":"+c.Key, "Baseline differs or cannot be checked", "agent", evidence)
	f["kind"] = "RISK"
	if kind == "DATABASE_SECURITY" {
		f["title"] = "数据库安全配置隐患"
		if c.RuleName != "" {
			f["title"] = c.RuleName
		}
		if c.RuleSeverity != "" {
			f["severity"] = c.RuleSeverity
		}
		evidence["ruleId"] = c.RuleID
		evidence["ruleName"] = c.RuleName
		f["externalId"] = fmt.Sprintf("database-baseline:%s:%x", c.RuleID, sha256.Sum256([]byte(c.Path+":"+c.Key)))
		evidence["ruleId"] = c.RuleID
		evidence["ruleName"] = c.RuleName
		evidence["scope"] = "CONFIGURATION_ONLY"
		evidence["action"] = "DETECT_ONLY"
		evidence["outcome"] = "NOT_MODIFIED"
		evidence["reason"] = "文件配置观察，不能证明运行实例已加载，也不能证明发生了明文连接"
		if status != "checked" {
			f["title"] = "数据库安全配置无法完整检查"
			f["severity"] = "INFO"
		}
	}
	return f
}
