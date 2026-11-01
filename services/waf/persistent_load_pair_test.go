package main

import (
	"testing"
	"time"
)

func TestPersistentComparisonDoesNotDelayWAFDispatchBehindBaseline(t *testing.T) {
	wafStarted := make(chan struct{})
	call := func(origin string, attack bool) (int, float64, string) {
		if origin == "baseline" {
			select {
			case <-wafStarted:
				return 200, 500, ""
			case <-time.After(time.Second):
				return 0, 0, "BASELINE_WAITED_FOR_WAF"
			}
		}
		close(wafStarted)
		return 403, 10, ""
	}
	sample := persistentPairedSample(call, "baseline", "waf", true)
	if sample.Status != 403 || sample.BaselineStatus != 200 || sample.Failure != "" || sample.WafMS != 10 || sample.BaselineMS != 500 || sample.AddedMS != -490 {
		t.Fatalf("baseline serialized WAF dispatch or lost paired evidence: %+v", sample)
	}
}

func TestPersistentComparisonKeepsBaselineFailures(t *testing.T) {
	call := func(origin string, _ bool) (int, float64, string) {
		if origin == "baseline" {
			return 0, 3000, "HTTP_REQUEST_FAILED"
		}
		return 200, 10, ""
	}
	sample := persistentPairedSample(call, "baseline", "waf", false)
	if sample.Status != 200 || sample.Failure != "BASELINE_HTTP_REQUEST_FAILED" {
		t.Fatalf("baseline failure was hidden: %+v", sample)
	}
}
