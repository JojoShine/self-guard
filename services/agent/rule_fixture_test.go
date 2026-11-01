package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestRuleFixtureUsesActualBaselineAndLogEvaluator(t *testing.T) {
	for _, tc := range []struct {
		body    string
		matched bool
		status  string
	}{
		{`{"rule":{"id":"r","kind":"BASELINE","config":{"path":"/must-not-be-read","mode":"0600"}},"asset":{"id":"a"},"fixture":{"mode":"0644"}}`, true, "COMPLETED"},
		{`{"rule":{"id":"r","kind":"BASELINE","config":{"path":"/must-not-be-read","mode":"0600"}},"asset":{"id":"a"},"fixture":{"mode":"0600"}}`, false, "COMPLETED"},
		{`{"rule":{"id":"r","kind":"BASELINE","config":{"type":"CONFIG_VALUE","path":"/must-not-be-read","key":"TOKEN","value":"private-expected"}},"asset":{"id":"a"},"fixture":{"content":"TOKEN=private-actual\nTOKEN=duplicate"}}`, true, "UNKNOWN"},
		{`{"rule":{"id":"r","kind":"LOG","config":{"contains":"failed","field":"message","threshold":2}},"asset":{"id":"a"},"fixture":{"lines":["failed","ok","failed"]}}`, true, "COMPLETED"},
	} {
		var out bytes.Buffer
		if err := runRuleTest(strings.NewReader(tc.body), &out); err != nil {
			t.Fatal(err)
		}
		var got struct {
			Matched bool   `json:"matched"`
			Status  string `json:"status"`
		}
		if json.Unmarshal(out.Bytes(), &got) != nil || got.Matched != tc.matched || got.Status != tc.status {
			t.Fatal(out.String())
		}
		if strings.Contains(out.String(), "private-") {
			t.Fatal("sensitive config value exposed")
		}
	}
}
