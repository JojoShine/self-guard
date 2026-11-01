package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"testing"
)

func TestSecLiveRequestPreservesObservedHTTPAndDeferredBody(t *testing.T) {
	rules, err := parseSecLangFiles([]secLangFile{{Name: "live.conf", Source: `SecRule REMOTE_ADDR "@ipMatch 198.51.100.7" "id:101,phase:1,pass"
SecRule REQUEST_PROTOCOL "@streq HTTP/1.0" "id:102,phase:1,pass"
SecRule REQUEST_HEADERS:X-Test "@streq second" "id:103,phase:1,pass"
SecRule REQUEST_HEADERS:Content-Type "@contains application/json" "id:104,phase:1,pass,ctl:requestBodyProcessor=JSON"
SecRule ARGS:json.q "@streq attack" "id:105,phase:2,deny,status:451"`}})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := prepareSecLangPlan(rules)
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"q":"attack"}`)
	r := httptest.NewRequest("POST", "/submit?q=safe", bytes.NewReader(body))
	r.Proto, r.ProtoMajor, r.ProtoMinor = "HTTP/1.0", 1, 0
	r.RemoteAddr = "198.51.100.7:23456"
	r.Header["X-Test"] = []string{"first", "second"}
	r.Header.Set("Content-Type", "application/json")
	wire := newSecLiveRequest(r, body)
	r.Header.Set("X-Test", "changed-after-freeze")
	body[0] = ' '
	result, err := evaluateSecLangRequest(plan, secLangFixture{Request: wire})
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"101", "102", "103", "104", "105"} {
		if !contains(result.Matches, id) {
			t.Fatalf("observed request field lost (%s): %+v", id, result)
		}
	}
	if !result.Blocked || result.Status != 451 {
		t.Fatalf("real body decision lost: %+v", result)
	}
	encoded, err := json.Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	var decoded secLiveRequest
	if json.Unmarshal(encoded, &decoded) != nil {
		t.Fatal("wire request cannot be decoded")
	}
	if _, err = evaluateSecLangRequest(plan, secLangFixture{Request: &decoded}); err != nil {
		t.Fatal(err)
	}
	for _, fixture := range []secLangFixture{
		{Request: wire, Variables: map[string][]string{}},
		{Request: wire, RequestBase64: base64.StdEncoding.EncodeToString([]byte("GET / HTTP/1.1\r\nHost: a\r\n\r\n"))},
	} {
		if _, err := evaluateSecLangRequest(plan, fixture); err == nil {
			t.Fatal("multiple request representations accepted")
		}
	}
}

func TestSecLiveRequestCrossesRealIsolatedPoolWithoutChangingFields(t *testing.T) {
	pool := newSecLangPool(poolTestBinary(t), 1)
	defer pool.close()
	files := []secLangFile{{Name: "live.conf", Source: `SecRule REMOTE_ADDR "@ipMatch 198.51.100.7" "id:111,phase:1,pass"
SecRule ARGS:q "@streq attack" "id:112,phase:2,deny,status:451"`}}
	for _, value := range []string{"attack", "safe", "attack"} {
		request := httptest.NewRequest("GET", "/?q="+value, nil)
		request.RemoteAddr = "198.51.100.7:23456"
		result, err := pool.evaluate(context.Background(), files, secLangFixture{Request: newSecLiveRequest(request, nil)})
		if err != nil || result.Blocked != (value == "attack") || !contains(result.Matches, "111") {
			t.Fatalf("isolated observed request: %+v %v", result, err)
		}
	}
	if pool.stats() != 1 {
		t.Fatal("observed request did not reuse isolated process")
	}
}
