package scanner

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

func TestSourceTextTransformsAndLengthHaveExactByteSemantics(t *testing.T) {
	threshold := 50
	rule := HTTPRule{ID: "source-conditions", Description: "Literal lowercasing is distinct from case-insensitive regex", Operator: "ALL", Conditions: []Condition{{Kind: "BODY_LENGTH", Comparison: "GT", Threshold: &threshold}, {Kind: "BODY_LOWER_CONTAINS", Value: "<html"}, {Kind: "HEADER_LOWER_CONTAINS", Header: "Content-Type", Value: "text/plain"}}}
	sample := RuleSample{Status: 200, Headers: http.Header{"Content-Type": []string{"TEXT/PLAIN"}}, Body: strings.Repeat("界", 20) + "<HTML"}
	result, err := CheckRule("GET", rule, sample)
	if err != nil || !result.Matched {
		t.Fatal(result, err)
	}
	rule.Conditions[1].Value = "<HTML"
	result, err = CheckRule("GET", rule, sample)
	if err != nil || result.Matched {
		t.Fatal("must not lowercase the literal when only the response is transformed", result, err)
	}
	delete(sample.Headers, "Content-Type")
	if _, err = CheckRule("GET", rule, sample); err == nil {
		t.Fatal("missing DSL header must not turn a negated condition into confirmation")
	}
}
func TestActualMissingRequiredHeaderIsInconclusive(t *testing.T) {
	engine, _, _ := httpFixture(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) })
	rule := HTTPRule{ID: "required-header", Description: "Missing expression input is not safe evidence", Operator: "ALL", Conditions: []Condition{{Kind: "HEADER_LOWER_CONTAINS", Header: "X-Fixture-Required", Value: "html", Negative: true}}}
	result := engine.HTTP(context.Background(), "GET", "/public", rule)
	if result.Outcome != "INCONCLUSIVE" || result.Reason != "REQUIRED_RESPONSE_FIELD_MISSING" {
		t.Fatal(result)
	}
}
func TestResponseLiteralIncludesHeaderAndBodyWithinTheSameActualResponse(t *testing.T) {
	engine, _, _ := httpFixture(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("owned-response-marker"))
	})
	rule := HTTPRule{ID: "raw-response", Description: "Upstream response includes headers and decoded body", Operator: "ALL", Conditions: []Condition{{Kind: "RESPONSE_CONTAINS", Value: "application/json"}, {Kind: "RESPONSE_CONTAINS", Value: "owned-response-marker"}}}
	result := engine.HTTP(context.Background(), "GET", "/public", rule)
	if result.Outcome != "CONFIRMED" || len(result.Evidence.Conditions) != 2 {
		t.Fatal(result)
	}
	rule.Conditions[0].Negative = true
	result = engine.HTTP(context.Background(), "GET", "/public", rule)
	if result.Outcome != "NOT_FOUND" {
		t.Fatal(result)
	}
}
