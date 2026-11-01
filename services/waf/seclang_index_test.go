package main

import (
	"bytes"
	"encoding/json"
	"io"
	"testing"
)

func TestSecLangIndexRetainsRulePhaseAndParanoiaWithoutExecutingRequest(t *testing.T) {
	fixture := secLangFixture{Files: []secLangFile{{Name: "rules.conf", Source: `SecRule ARGS:q "@contains attack" "id:1001,phase:2,tag:'paranoia-level/2',deny"
SecRule RESPONSE_BODY "@contains secret" "id:1002,phase:4,tag:'paranoia-level/1',deny"`}}}
	raw, _ := json.Marshal(fixture)
	var output bytes.Buffer
	if err := runSecLangCLI(bytes.NewReader(raw), &output, false, true); err != nil {
		t.Fatal(err)
	}
	var result struct {
		Compatibility secCompatibility `json:"compatibility"`
		Rules         []secRuleIndex   `json:"rules"`
	}
	if err := json.Unmarshal(output.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if len(result.Rules) != 2 || result.Rules[0].ID != "1001" || result.Rules[0].ParanoiaLevel != 2 || result.Rules[0].Phase != 2 || result.Rules[1].Phase != 4 {
		t.Fatalf("incomplete policy index: %+v", result)
	}
	if result.Compatibility.OutsideProfile != 1 {
		t.Fatalf("outbound rule misclassified: %+v", result.Compatibility)
	}
}
func TestSecLangCLIRejectsTrailingJSONInsteadOfIgnoringUnsignedContent(t *testing.T) {
	// A valid first envelope followed by another value must never be accepted.
	fixture := secLangFixture{Files: []secLangFile{{Name: "rules.conf", Source: `SecAction "id:1001,phase:1,pass"`}}}
	raw, _ := json.Marshal(fixture)
	raw = append(raw, []byte(` {"files":[]}`)...)
	if err := runSecLangCLI(bytes.NewReader(raw), io.Discard, false); err == nil {
		t.Fatal("trailing JSON accepted")
	}
}
