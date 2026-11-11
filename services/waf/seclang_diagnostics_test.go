package main

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSecLangDiagnosticTranscriptUsesExecutedMatchesAndIsOptIn(t *testing.T) {
	input := secLangFixture{Files: []secLangFile{{Name: "a.conf", Source: `SecRule ARGS:q "@contains unique-secret" "id:1001,phase:2,deny,msg:'Matched %{MATCHED_VAR_NAME}',logdata:'%{MATCHED_VAR} found within %{MATCHED_VAR_NAME}:'"`}}, Variables: map[string][]string{"ARGS:q": {"unique-secret-value"}}}
	raw, _ := json.Marshal(input)
	var normal, diagnostic bytes.Buffer
	if err := runSecLangCLI(bytes.NewReader(raw), &normal, true); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(normal.String(), "unique-secret-value") {
		t.Fatal("normal result exposed matched raw data")
	}
	if err := runSecLangCLIOptions(bytes.NewReader(raw), &diagnostic, true, false, true); err != nil {
		t.Fatal(err)
	}
	var result secResult
	if json.Unmarshal(diagnostic.Bytes(), &result) != nil || len(result.DiagnosticLog) != 1 || !strings.Contains(result.DiagnosticLog[0], `[id "1001"] [msg "Matched ARGS:q"]`) || !strings.Contains(result.DiagnosticLog[0], "unique-secret-value found within ARGS:q:") {
		t.Fatalf("actual log semantics missing: %s", diagnostic.String())
	}
	input.Files[0].Source = `SecRule ARGS:q "@contains unique-secret" "id:1001,phase:2,deny,nolog,msg:'must not log'"`
	raw, _ = json.Marshal(input)
	diagnostic.Reset()
	if err := runSecLangCLIOptions(bytes.NewReader(raw), &diagnostic, true, false, true); err != nil {
		t.Fatal(err)
	}
	result = secResult{}
	json.Unmarshal(diagnostic.Bytes(), &result)
	if len(result.DiagnosticLog) != 0 {
		t.Fatal("nolog action ignored")
	}
}

func TestMultipartInvalidHeaderDiagnosticUsesActualParserError(t *testing.T) {
	for _, header := range []string{"\x0eContent-Disposition", "Content-Disposition\x0e", "Content-\x0eDisposition"} {
		body := "--boundary\r\n" + header + ": form-data; name=\"post\"\r\n\r\nvalue\r\n--boundary--\r\n"
		r := httptest.NewRequest("POST", "http://fixture.test/", strings.NewReader(body))
		r.Header.Set("Content-Type", "multipart/form-data; boundary=boundary")
		state := secRequestState{request: r, body: []byte(body)}
		input, err := state.load("", false)
		if err != nil {
			t.Fatal(err)
		}
		if got := input["REQBODY_ERROR_MSG"]; len(got) != 1 || got[0] != errSecMultipartHeader.Error() {
			t.Fatalf("invalid header parser error lost: %v", got)
		}
	}
}
