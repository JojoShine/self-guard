package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPolicyManagementUsesInspectionWithoutForwarding(t *testing.T) {
	hits := 0
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits++ }))
	defer up.Close()
	e := newEngine()
	if err := e.update(Config{Sites: []Site{{ID: "a", Hostname: "a", Upstream: up.URL, Mode: "BLOCK", Enabled: true}}}); err != nil {
		t.Fatal(err)
	}
	handler := e.policyTestHandler("component-secret")
	for _, tc := range []struct {
		token, body string
		status      int
		contains    string
	}{
		{"", `{}`, 401, ""}, {"component-secret", `{"siteId":"a","method":"GET","path":"/?q=union%20select"}`, 200, `"ruleId":"SQLI"`},
		{"component-secret", `{"siteId":"a","method":"POST","path":"/","headers":{"Content-Type":"application/json"},"body":"{\"q\":\"<script>\"}"}`, 200, `"ruleId":"XSS"`},
		{"component-secret", `{"siteId":"a","method":"GET","path":"/"}`, 200, `"action":"ALLOW"`},
	} {
		r := httptest.NewRequest("POST", "/test", strings.NewReader(tc.body))
		r.Header.Set("Authorization", "Bearer "+tc.token)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != tc.status || !strings.Contains(w.Body.String(), tc.contains) {
			t.Fatal(w.Code, w.Body.String())
		}
	}
	if hits != 0 || e.totalRequests.Load() != 0 || len(e.rates) != 0 {
		t.Fatal("policy test affected live traffic")
	}
}
