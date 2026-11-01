package main

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestSecLangStreamCompilesOnceAndKeepsStateAndErrorsPerRequest(t *testing.T) {
	var input, output bytes.Buffer
	initial := secLangFixture{Files: []secLangFile{{Name: "rules.conf", Source: `SecRule ARGS:q "@contains attack" "id:1001,phase:2,deny,setvar:'tx.hit=1'"`}}}
	raw, _ := json.Marshal(initial)
	if err := writeSecFrame(&input, raw); err != nil {
		t.Fatal(err)
	}
	for _, fixture := range []secLangFixture{{Variables: map[string][]string{"ARGS:q": {"attack"}}}, {Variables: map[string][]string{"ARGS:q": {"safe"}}}, {Variables: map[string][]string{"TX:hit": {"1"}}}, {Variables: map[string][]string{"ARGS:q": {"safe"}}}} {
		raw, _ = json.Marshal(fixture)
		writeSecFrame(&input, raw)
	}
	if err := runSecLangStream(&input, &output); err != nil {
		t.Fatal(err)
	}
	ready, err := readSecFrame(&output, 2<<20)
	if err != nil {
		t.Fatal(err)
	}
	var header secStreamResponse
	if json.Unmarshal(ready, &header) != nil || header.Kind != "READY" || len(header.Digest) != 64 {
		t.Fatalf("missing immutable load receipt: %s", ready)
	}
	for n := 0; n < 4; n++ {
		raw, err = readSecFrame(&output, 2<<20)
		if err != nil {
			t.Fatal(err)
		}
		var response secStreamResponse
		if json.Unmarshal(raw, &response) != nil || response.Sequence != n+1 {
			t.Fatal("request correlation lost")
		}
		if n == 2 {
			if response.Kind != "ERROR" || response.Status != "INCOMPLETE" {
				t.Fatal("failed inspection presented as clean")
			}
		} else if response.Kind != "RESULT" || response.Result == nil || response.Result.Blocked != (n == 0) {
			t.Fatalf("state or failure leaked: %s", raw)
		}
	}
}
func TestSecLangStreamRejectsOversizedTruncatedAndRuleReplacementFrames(t *testing.T) {
	var input, output bytes.Buffer
	input.Write([]byte{0, 64, 0, 1})
	if _, err := readSecFrame(&input, 4<<20); err == nil {
		t.Fatal("oversized frame accepted")
	}
	input.Reset()
	input.Write([]byte{0, 0, 0, 4, 1})
	if _, err := readSecFrame(&input, 4<<20); err == nil {
		t.Fatal("truncated frame accepted")
	}
	input.Reset()
	raw, _ := json.Marshal(secLangFixture{Files: []secLangFile{{Name: "a.conf", Source: `SecAction "id:1,phase:1,pass"`}}})
	writeSecFrame(&input, raw)
	writeSecFrame(&input, raw)
	if err := runSecLangStream(&input, &output); err != nil {
		t.Fatal(err)
	}
	readSecFrame(&output, 2<<20)
	body, _ := readSecFrame(&output, 2<<20)
	var response secStreamResponse
	json.Unmarshal(body, &response)
	if response.Kind != "ERROR" {
		t.Fatal("request replaced immutable rule package")
	}
}
