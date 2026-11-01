package main

import "strings"

// Persistent collection state is outside this inbound profile. A disabled
// branch is excluded only when the whole source proves its guard stays zero.
// Any ambiguous dynamic writer removes that proof and keeps the normal gate.
func secProfileConstants(rules []secRule) map[string]string {
	constants := map[string]string{"enable_default_collections": "0"}
	var visit func(secRule)
	visit = func(rule secRule) {
		for _, action := range rule.ActionOrder {
			if action.Name != "setvar" {
				continue
			}
			name, value, _ := strings.Cut(action.Value, "=")
			name = strings.ToLower(name)
			if offset := strings.Index(name, "%{"); offset >= 0 {
				prefix := name[:offset]
				for key := range constants {
					if strings.HasPrefix("tx."+key, prefix) {
						delete(constants, key)
					}
				}
			} else if strings.HasPrefix(name, "tx.") {
				key := strings.TrimPrefix(name, "tx.")
				if expected, known := constants[key]; known && value != expected {
					delete(constants, key)
				}
			}
		}
		for _, child := range rule.Chain {
			visit(child)
		}
	}
	for _, rule := range rules {
		visit(rule)
	}
	return constants
}
func secProfileConditionFalse(rule secRule, constants map[string]string) bool {
	if rule.Directive != "SecRule" || rule.Operator != "eq" || rule.Negated || strings.ContainsAny(rule.Targets, "|!&%") || strings.Contains(rule.Operand, "%{") {
		return false
	}
	collection, key, keyed := strings.Cut(rule.Targets, ":")
	if !keyed || !strings.EqualFold(collection, "TX") {
		return false
	}
	value, known := constants[strings.ToLower(key)]
	if !known {
		return false
	}
	for _, transform := range rule.Actions["t"] {
		if !strings.EqualFold(transform, "none") {
			return false
		}
	}
	matched, err := matchSecOperator(rule.Operator, rule.Operand, value)
	return err == nil && !matched
}
func secRuleTreeSize(rule secRule) int {
	count := 1
	for _, child := range rule.Chain {
		count += secRuleTreeSize(child)
	}
	return count
}
