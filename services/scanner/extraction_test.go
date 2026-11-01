package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

func TestActualExtractionKeepsOnlyBoundedDigestsAndLengths(t *testing.T) {
	engine, _, budget := httpFixture(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "[core]\nurl=https://alice:fixture-secret@owned.invalid/repo")
	})
	rule := HTTPRule{ID: "source-extractor", Description: "Actual exposure marker with private extracted values", Operator: "ALL", Conditions: []Condition{{Kind: "BODY_CONTAINS", Value: "[core]"}}, Extractors: []ExtractionSpec{{Kind: "BODY_REGEX", Value: `url ?= ?https?://(.*:.*)@`, Group: 1, Name: "Credential format"}}}
	result := engine.HTTP(context.Background(), "GET", "/public", rule)
	if result.Outcome != "CONFIRMED" || len(result.Evidence.Extractions) != 1 {
		t.Fatal(result)
	}
	value := result.Evidence.Extractions[0]
	if value.MatchCount != 1 || len(value.Values) != 1 || value.Values[0].SHA256 != hashBytes([]byte("alice:fixture-secret")) || value.Values[0].Bytes != len("alice:fixture-secret") {
		t.Fatal(value)
	}
	raw, _ := json.Marshal(result)
	if strings.Contains(string(raw), "fixture-secret") {
		t.Fatal("private extracted content persisted")
	}
	rule.Extractors[0].Group = 2
	result = engine.HTTP(context.Background(), "GET", "/public", rule)
	if result.Outcome != "INCONCLUSIVE" || budget.calls.Load() != 1 {
		t.Fatal("invalid capture group must reject before traffic", result)
	}
}
func TestExtractionStopsAtItsMatchBudget(t *testing.T) {
	engine, _, _ := httpFixture(t, func(w http.ResponseWriter, r *http.Request) {
		for i := 0; i < 40; i++ {
			fmt.Fprintf(w, "user%d:value%d\n", i, i)
		}
	})
	rule := HTTPRule{ID: "bounded-extractor", Description: "Bounded extraction metadata", Operator: "ALL", Conditions: []Condition{{Kind: "STATUS", Status: 200}}, Extractors: []ExtractionSpec{{Kind: "BODY_REGEX", Value: `user[0-9]+:value[0-9]+`}}}
	result := engine.HTTP(context.Background(), "GET", "/public", rule)
	if result.Outcome != "CONFIRMED" || !result.Evidence.Extractions[0].Truncated || result.Evidence.Extractions[0].MatchCount != 16 || len(result.Evidence.Extractions[0].Values) > 16 {
		t.Fatal(result)
	}
}
