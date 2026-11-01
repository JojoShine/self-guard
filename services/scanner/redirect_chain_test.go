package scanner

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"testing"
)

func TestSourceRedirectModeEvaluatesEachResponseWithoutInventingTheMatchedHop(t *testing.T) {
	engine, _, budget := httpFixture(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/public/start" {
			w.Header().Set("Location", "/public/final")
			w.WriteHeader(302)
			fmt.Fprint(w, "owned-first-response")
			return
		}
		fmt.Fprint(w, "normal-final-page")
	})
	limit := 3
	rule := HTTPRule{ID: "source-chain", Description: "Original template evaluates redirect responses independently", Operator: "ALL", MaxRedirects: &limit, ResponseMode: "ANY_REDIRECT", Conditions: []Condition{{Kind: "STATUS", Status: 302}, {Kind: "BODY_CONTAINS", Value: "owned-first-response"}}}
	result := engine.HTTP(context.Background(), "GET", "/public/start", rule)
	if result.Outcome != "CONFIRMED" || result.Evidence.Status != 302 || len(result.Evidence.Requests) != 2 || result.Evidence.EvaluatedResponseIndex == nil || *result.Evidence.EvaluatedResponseIndex != 0 || len(result.Evidence.Responses) != 2 || !result.Evidence.Responses[0].Matched || result.Evidence.Responses[1].Matched {
		t.Fatal(result)
	}
	rule.ResponseMode = ""
	result = engine.HTTP(context.Background(), "GET", "/public/start", rule)
	if result.Outcome != "NOT_FOUND" || result.Evidence.Status != 200 || budget.calls.Load() != 4 {
		t.Fatal(result)
	}
}
func TestSourceRedirectModeRetainsTenHopBudgetAndRejectsTheEleventh(t *testing.T) {
	engine, _, budget := httpFixture(t, func(w http.ResponseWriter, r *http.Request) {
		n, _ := strconv.Atoi(strings.TrimPrefix(r.URL.Path, "/public/"))
		if n < 10 {
			w.Header().Set("Location", fmt.Sprintf("/public/%d", n+1))
			w.WriteHeader(302)
		}
		fmt.Fprintf(w, "hop-%d", n)
	})
	limit := 10
	rule := HTTPRule{ID: "ten-redirects", Description: "Preserves explicit upstream ten redirect budget", Operator: "ALL", MaxRedirects: &limit, ResponseMode: "ANY_REDIRECT", Conditions: []Condition{{Kind: "BODY_CONTAINS", Value: "hop-0"}}}
	result := engine.HTTP(context.Background(), "GET", "/public/0", rule)
	if result.Outcome != "CONFIRMED" || len(result.Evidence.Requests) != 11 || budget.calls.Load() != 11 {
		t.Fatal(result)
	}
	limit = 9
	result = engine.HTTP(context.Background(), "GET", "/public/0", rule)
	if result.Outcome != "INCONCLUSIVE" || result.Reason != "REDIRECT_LIMIT" || budget.calls.Load() != 21 {
		t.Fatal(result)
	}
}
func TestSourceChainNeverTurnsMissingFieldsOrTruncatedRedirectsIntoNoRisk(t *testing.T) {
	engine, _, _ := httpFixture(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/public/start" {
			w.Header().Set("Location", "/public/final")
			w.WriteHeader(302)
			fmt.Fprint(w, "owned-marker")
			return
		}
		w.WriteHeader(204)
	})
	limit := 3
	rule := HTTPRule{ID: "missing-chain-input", Description: "Missing required fields do not confirm negation", Operator: "ALL", MaxRedirects: &limit, ResponseMode: "ANY_REDIRECT", Conditions: []Condition{{Kind: "HEADER_FIELD_CONTAINS", Header: "X-Required-Field", Value: "missing", Negative: true}}}
	result := engine.HTTP(context.Background(), "GET", "/public/start", rule)
	if result.Outcome != "INCONCLUSIVE" || result.Reason != "REQUIRED_RESPONSE_FIELD_MISSING" {
		t.Fatal(result)
	}
}

func TestSourceChainDoesNotAcceptEarlierMarkerWhenRedirectLeavesApprovedPaths(t *testing.T) {
	engine, _, budget := httpFixture(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "/private")
		w.WriteHeader(302)
		fmt.Fprint(w, "owned-earlier-marker")
	})
	limit := 10
	rule := HTTPRule{ID: "chain-scope", Description: "Do not follow outside approved prefix", Operator: "ALL", MaxRedirects: &limit, ResponseMode: "ANY_REDIRECT", Conditions: []Condition{{Kind: "BODY_CONTAINS", Value: "owned-earlier-marker"}}}
	result := engine.HTTP(context.Background(), "GET", "/public/start", rule)
	if result.Outcome != "INCONCLUSIVE" || result.Reason != "OUT_OF_SCOPE" || budget.calls.Load() != 1 {
		t.Fatal(result)
	}
}
