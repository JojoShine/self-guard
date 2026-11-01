package scanner

import (
	"context"
	"net/http"
	"testing"
)

func TestGroupedMatcherPreservesAndOfOrAndNegativeConditions(t *testing.T) {
	rule := HTTPRule{ID: "vendor-groups", Description: "Grouped original source conditions", Operator: "ALL", Groups: []ConditionGroup{{Operator: "ANY", Conditions: []Condition{{Kind: "BODY_CONTAINS", Value: "[core]"}, {Kind: "BODY_CONTAINS", Value: "[credentials]"}}}, {Operator: "ALL", Conditions: []Condition{{Kind: "BODY_REGEX", Value: "(?i)<html", Negative: true}, {Kind: "STATUS", Status: 200}}}}}
	for _, row := range []struct {
		body   string
		status int
		want   bool
	}{{"[core]\n", 200, true}, {"[credentials]\n", 200, true}, {"[core]<HTML", 200, false}, {"normal", 200, false}, {"[core]", 404, false}} {
		result, err := CheckRule("GET", rule, RuleSample{Status: row.status, Headers: http.Header{}, Body: row.body})
		if err != nil || result.Matched != row.want || len(result.Groups) != 2 {
			t.Fatalf("grouped match %+v: %+v %v", row, result, err)
		}
	}
	rule.Conditions = []Condition{{Kind: "STATUS", Status: 200}}
	if _, err := CheckRule("GET", rule, RuleSample{Status: 200}); err == nil {
		t.Fatal("mixed flat and grouped rule accepted")
	}
}
func TestNoRedirectProfileEvaluatesActualRedirectWithoutFollowing(t *testing.T) {
	engine, dial, budget := httpFixture(t, func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/public/next", 302) })
	zero := 0
	rule := HTTPRule{ID: "no-redirect", Description: "Vendor defaults do not follow redirects", Operator: "ALL", MaxRedirects: &zero, Conditions: []Condition{{Kind: "STATUS", Status: 302}}}
	result := engine.HTTP(context.Background(), "GET", "/public/start", rule)
	if result.Outcome != "CONFIRMED" || result.Evidence.Status != 302 || dial.calls.Load() != 1 || budget.calls.Load() != 1 {
		t.Fatalf("redirect semantic changed: %+v", result)
	}
}
