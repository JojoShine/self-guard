package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSecLangHTTPTestingUsesBoundedWarmProcessesWithRealResults(t *testing.T) {
	handler := newSecLangHTTPHandler("private-component-test-token", true, poolTestBinary(t))
	defer handler.Close()
	server := httptest.NewServer(handler)
	defer server.Close()
	files := []secLangFile{{Name: "a.conf", Source: `SecRule ARGS:q "@contains attack" "id:1001,phase:2,deny,status:451"`}}
	for _, tc := range []struct {
		token, value string
		code         int
		blocked      bool
	}{{"wrong", "attack", 401, false}, {"private-component-test-token", "attack", 200, true}, {"private-component-test-token", "safe", 200, false}} {
		raw, _ := json.Marshal(secLangFixture{Files: files, Variables: map[string][]string{"ARGS:q": {tc.value}}})
		request, _ := http.NewRequest("POST", server.URL, bytes.NewReader(raw))
		request.Header.Set("Authorization", "Bearer "+tc.token)
		response, err := server.Client().Do(request)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(response.Body)
		response.Body.Close()
		if response.StatusCode != tc.code {
			t.Fatalf("%d: %s", response.StatusCode, body)
		}
		if tc.code == 200 {
			var result secResult
			if json.Unmarshal(body, &result) != nil || result.Blocked != tc.blocked {
				t.Fatalf("invalid real worker decision: %s", body)
			}
			if tc.blocked && result.Status != 451 {
				t.Fatal("configured block status lost")
			}
		}
	}
	if handler.pool.stats() != 1 {
		t.Fatal("HTTP test spawned a process per transaction")
	}
	raw, _ := json.Marshal(secLangFixture{Files: files, RequestBase64: "AA=="})
	request, _ := http.NewRequest("POST", server.URL, bytes.NewReader(raw))
	request.Header.Set("Authorization", "Bearer private-component-test-token")
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != 422 {
		t.Fatal("malformed inspection presented as successful HTTP testing")
	}
}

func TestManagementCheckReclaimsItsIdleWorkerWhileThreeLiveSlotsStayWarm(t *testing.T) {
	binary := poolTestBinary(t)
	live := newSecLangPool(binary, 3)
	defer live.close()
	files := []secLangFile{{Name: "management.conf", Source: `SecRule ARGS:q "@contains attack" "id:42122,phase:2,deny"`}}
	policy, _ := prepareSecPoolPolicy(files)
	if err := live.warmPolicy(context.Background(), policy); err != nil {
		t.Fatal(err)
	}
	check, evaluate := newSecLangManagementHandlers("private-component-test-token", binary)
	defer evaluate.Close()
	call := func(handler http.Handler, fixture secLangFixture) {
		t.Helper()
		raw, _ := json.Marshal(fixture)
		request := httptest.NewRequest("POST", "/seclang", bytes.NewReader(raw))
		request.Header.Set("Authorization", "Bearer private-component-test-token")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != 200 {
			t.Fatalf("management starved by idle worker: %d %s", response.Code, response.Body)
		}
	}
	call(evaluate, secLangFixture{Files: files, Variables: map[string][]string{"ARGS:q": {"attack"}}})
	if len(secWorkerSlots) != 4 {
		t.Fatal("fixture did not fill the three live and one management slots")
	}
	call(check, secLangFixture{Files: files})
	if len(secWorkerSlots) != 3 {
		t.Fatal("check retained its one-shot worker or stopped live workers")
	}
	call(evaluate, secLangFixture{Files: files, Variables: map[string][]string{"ARGS:q": {"safe"}}})
	if len(secWorkerSlots) != 4 || live.stats() != 3 {
		t.Fatal("management displaced live workers or exceeded the global limit")
	}
}
