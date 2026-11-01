package main

import (
	"errors"
	"strings"
)

// Explicit target updates operate on an immutable copy, after their target's
// declaration. Unknown IDs and syntax fail compilation instead of disappearing.
func secCompileTargets(source []secRule) ([]secRule, error) {
	result := make([]secRule, 0, len(source))
	byID := map[string]int{}
	for _, rule := range source {
		if rule.Directive != "SecRuleUpdateTargetById" {
			if rule.ID != "" {
				byID[rule.ID] = len(result)
			}
			result = append(result, rule)
			continue
		}
		index, ok := byID[rule.Operand]
		if !ok || result[index].Directive != "SecRule" {
			return nil, errors.New("target update references unknown preceding rule")
		}
		if _, err := secParseSelectors(rule.Targets); err != nil || rule.Targets == "" || strings.Contains(rule.Targets, "%{") {
			return nil, errors.New("invalid static target update")
		}
		result[index].Targets += "|" + rule.Targets
	}
	return result, nil
}
