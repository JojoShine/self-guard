package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"
)

func secRawPhaseFixture(t *testing.T, source, contentType, body string) secResult {
	t.Helper()
	raw := fmt.Sprintf("POST / HTTP/1.1\r\nHost: fixture.test\r\nContent-Type: %s\r\nContent-Length: %d\r\n\r\n%s", contentType, len(body), body)
	input, _ := json.Marshal(secLangFixture{Files: []secLangFile{{Name: "phases.conf", Source: source}}, RequestBase64: base64.StdEncoding.EncodeToString([]byte(raw))})
	var out bytes.Buffer
	if err := runSecLangCLI(bytes.NewReader(input), &out, true); err != nil {
		t.Fatal(err)
	}
	var result secResult
	if err := json.Unmarshal(out.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	return result
}
func TestSecLangRawBodyIsParsedAfterHeaderPhase(t *testing.T) {
	result := secRawPhaseFixture(t, `SecRule ARGS_POST:q "@contains attack" "id:2810,phase:1,deny"
SecRule ARGS_POST:q "@contains attack" "id:2811,phase:2,deny"`, "application/x-www-form-urlencoded", "q=attack")
	if !result.Blocked || len(result.Matches) != 1 || result.Matches[0] != "2811" {
		t.Fatalf("body visible too early: %+v", result)
	}
}
func TestSecLangHeaderPhaseCanSelectTheBodyProcessor(t *testing.T) {
	result := secRawPhaseFixture(t, `SecAction "id:2812,phase:1,pass,ctl:requestBodyProcessor=URLENCODED,ctl:forceRequestBodyVariable=On"
SecRule ARGS_POST:q "@contains attack" "id:2813,phase:2,deny"`, "text/plain", "q=attack")
	if !result.Blocked || result.Matches[len(result.Matches)-1] != "2813" {
		t.Fatalf("processor ignored: %+v", result)
	}
}
func TestSecLangRawMalformedBodyHasProtocolEvidenceAndIncompleteCoverage(t *testing.T) {
	result := secRawPhaseFixture(t, `SecRule REQBODY_ERROR "@eq 1" "id:2814,phase:2,deny"`, "application/json", `{"broken":`)
	if !result.Blocked || len(result.Incomplete) == 0 {
		t.Fatalf("malformed body reported clean: %+v", result)
	}
}
func TestSecLangBodyControlOutsideHeadersDoesNotPassPublication(t *testing.T) {
	rules, err := parseSecLang("wrong-phase.conf", `SecAction "id:2815,phase:2,pass,ctl:requestBodyProcessor=URLENCODED"`)
	if err != nil {
		t.Fatal(err)
	}
	if secLangCompatibility(rules).Publishable {
		t.Fatal("late body processor change accepted")
	}
}

func TestSecLangMalformedContentTypeStillReachesProtocolAndRawBodyRules(t *testing.T) {
	result := secRawPhaseFixture(t, `SecRule REQUEST_HEADERS:Content-Type "@contains broken" "id:2870,phase:1,pass"
SecRule REQBODY_PROCESSOR "@streq " "id:2871,phase:1,pass,ctl:forceRequestBodyVariable=On"
SecRule REQUEST_BODY "@contains attack" "id:2872,phase:2,deny"`, `application/json; broken="`, "attack")
	if !result.Blocked || len(result.Incomplete) == 0 || len(result.Matches) != 3 {
		t.Fatalf("malformed type bypassed protocol/raw inspection or reported complete: %+v", result)
	}
}
