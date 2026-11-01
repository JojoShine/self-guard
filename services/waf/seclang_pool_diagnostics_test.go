package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"testing"
	"time"
)

func TestSecPoolDiagnosticsBoundCapacityHistoryAndCopyState(t *testing.T) {
	pool := newSecLangPool("unused", 3)
	defer pool.close()
	for i := 0; i < cap(pool.pending); i++ {
		pool.pending <- struct{}{}
	}
	pool.slots[0].busy = true
	pool.slots[0].busySince = time.Now().Add(-2 * time.Millisecond)
	for i := 0; i < 70; i++ {
		if _, err := pool.evaluatePolicy(context.Background(), nil, secLangFixture{}); !errors.Is(err, errSecPoolCapacity) {
			t.Fatal("capacity rejection changed", err)
		}
	}
	value := pool.diagnostics()
	if value.Pending != 64 || value.PeakPending != 64 || value.CapacityRejected != 70 || len(value.Rejections) != 64 {
		t.Fatalf("unbounded or incomplete counters: %+v", value)
	}
	if !value.Rejections[0].Slots[0].Busy || value.Rejections[0].Slots[0].WorkerReady || value.Rejections[0].Slots[0].BusyMillis < 2 {
		t.Fatalf("replacement pressure missing: %+v", value.Rejections[0])
	}
	value.Rejections[0].Slots[0].Busy = false
	if !pool.diagnostics().Rejections[0].Slots[0].Busy {
		t.Fatal("diagnostics exposed mutable pool history")
	}
}

func TestSecPoolDiagnosticsRequireComponentIdentityAndReadOnlyMethod(t *testing.T) {
	pool := newSecLangPool("unused", 3)
	defer pool.close()
	runtime := &engine{rulePool: pool}
	for _, tc := range []struct {
		method, token string
		status        int
	}{
		{"GET", "", 401}, {"GET", "wrong", 401}, {"POST", "private-test-token", 405}, {"GET", "private-test-token", 200},
	} {
		request := httptest.NewRequest(tc.method, "/seclang/pool", nil)
		request.Header.Set("Authorization", "Bearer "+tc.token)
		response := httptest.NewRecorder()
		runtime.rulePoolHandler("private-test-token").ServeHTTP(response, request)
		if response.Code != tc.status {
			t.Fatalf("%s: got %d want %d", tc.method, response.Code, tc.status)
		}
		if tc.status == 200 {
			var result secPoolDiagnostics
			if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil || result.Capacity != 64 || len(result.Slots) != 3 {
				t.Fatal("invalid private pool response", err)
			}
		}
	}
	request := httptest.NewRequest("GET", "/seclang/pool", nil)
	request.Header.Set("Authorization", "Bearer private-test-token")
	response := httptest.NewRecorder()
	(&engine{}).rulePoolHandler("private-test-token").ServeHTTP(response, request)
	if response.Code != 503 {
		t.Fatal("absent runtime pool reported as healthy")
	}
}
