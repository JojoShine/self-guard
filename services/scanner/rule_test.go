package scanner

import (
	"net/http"
	"strings"
	"testing"
)

func TestOfflineRuleUsesTheLiveConditionSemantics(t *testing.T) {
	rule := matchingRule()
	positive := RuleSample{Status: 200, Headers: http.Header{"Content-Type": []string{"text/plain"}}, Body: "exposed-123"}
	result, err := CheckRule("GET", rule, positive)
	if err != nil || !result.Matched || len(result.Conditions) != 3 {
		t.Fatalf("positive fixture: %+v %v", result, err)
	}
	negative := positive
	negative.Body = "normal response"
	result, err = CheckRule("GET", rule, negative)
	if err != nil || result.Matched || result.Conditions[2].Matched {
		t.Fatalf("negative fixture: %+v %v", result, err)
	}
	rule.Operator = "ANY"
	result, err = CheckRule("GET", rule, negative)
	if err != nil || !result.Matched {
		t.Fatalf("ANY semantics differ: %+v %v", result, err)
	}
}
func TestOfflineRuleRejectsUnsupportedAndUnboundedSamples(t *testing.T) {
	for _, test := range []struct {
		method string
		rule   HTTPRule
		sample RuleSample
	}{
		{"POST", matchingRule(), RuleSample{Status: 200}},
		{"HEAD", matchingRule(), RuleSample{Status: 200}},
		{"GET", matchingRule(), RuleSample{Status: 0}},
		{"GET", matchingRule(), RuleSample{Status: 200, Body: strings.Repeat("x", (1<<20)+1)}},
		{"GET", matchingRule(), RuleSample{Status: 200, Headers: http.Header{"X-Test": []string{strings.Repeat("x", 16<<10)}}}},
	} {
		if _, err := CheckRule(test.method, test.rule, test.sample); err == nil {
			t.Fatal("invalid sample accepted")
		}
	}
	rule := matchingRule()
	rule.Conditions[2].Value = "(?=unsafe)"
	if _, err := CheckRule("GET", rule, RuleSample{Status: 200}); err == nil {
		t.Fatal("unsupported RE2 expression accepted")
	}
}
