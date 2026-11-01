package main

import (
	"crypto/sha256"
	"fmt"
)

type secMatchEvidence struct {
	RuleID          string   `json:"ruleId"`
	Variable        string   `json:"variable"`
	ValueSHA256     string   `json:"valueSha256"`
	ValueBytes      int      `json:"valueBytes"`
	MessageTemplate string   `json:"messageTemplate,omitempty"`
	Tags            []string `json:"tags,omitempty"`
	LogDataSHA256   string   `json:"logDataSha256,omitempty"`
	LogDataBytes    int      `json:"logDataBytes,omitempty"`
}

func secEvidence(rule secRule, variable secVariable, logData string) secMatchEvidence {
	bounded := func(value string, limit int) string {
		if len(value) > limit {
			return value[:limit]
		}
		return value
	}
	evidence := secMatchEvidence{RuleID: rule.ID, Variable: bounded(variable.name, 256), ValueSHA256: fmt.Sprintf("%x", sha256.Sum256([]byte(variable.value))), ValueBytes: len(variable.value), MessageTemplate: bounded(secFirst(rule.Actions, "msg"), 512)}
	for i, tag := range rule.Actions["tag"] {
		if i >= 20 {
			break
		}
		evidence.Tags = append(evidence.Tags, bounded(tag, 128))
	}
	if logData != "" {
		evidence.LogDataSHA256 = fmt.Sprintf("%x", sha256.Sum256([]byte(logData)))
		evidence.LogDataBytes = len(logData)
	}
	return evidence
}
