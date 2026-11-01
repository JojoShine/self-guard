package main

import "testing"

func TestSecLangStructuredBodyUsesParsedValuesWithoutTreatingNamesAsPayload(t *testing.T) {
	for _, sample := range []struct{ media, body string }{
		{"application/xml", `<attack-name ordinary="value">safe</attack-name>`},
		{"application/json", `{"attack-name":"safe"}`},
		{"multipart/form-data; boundary=x", "--x\r\nContent-Disposition: form-data; name=\"attack-name\"\r\n\r\nsafe\r\n--x--\r\n"},
	} {
		result := secRawPhaseFixture(t, `SecRule REQUEST_BODY "@contains attack" "id:2850,phase:2,deny"`, sample.media, sample.body)
		if result.Blocked {
			t.Fatalf("structured names exposed as raw payload for %s: %+v", sample.media, result)
		}
	}
	result := secRawPhaseFixture(t, `SecRule XML:/* "@contains attack" "id:2851,phase:2,deny"`, "application/xml", `<ordinary>attack</ordinary>`)
	if !result.Blocked {
		t.Fatal("XML content lost")
	}
}

func TestSecLangUnknownBodyRequiresExplicitForceAndRetainsURLencodedRawBody(t *testing.T) {
	rule := `SecRule REQUEST_BODY "@contains attack" "id:2852,phase:2,deny"`
	if secRawPhaseFixture(t, rule, "text/plain", "attack").Blocked {
		t.Fatal("unknown body exposed without explicit force")
	}
	if !secRawPhaseFixture(t, `SecAction "id:2853,phase:1,pass,ctl:forceRequestBodyVariable=On"`+"\n"+rule, "text/plain", "attack").Blocked {
		t.Fatal("explicit raw-body inspection ignored")
	}
	if !secRawPhaseFixture(t, `SecRule REQBODY_PROCESSOR "!@rx (?:URLENCODED|MULTIPART|XML|JSON)" "id:2854,phase:1,pass,ctl:forceRequestBodyVariable=On"`+"\n"+rule, "text/plain", "attack").Blocked {
		t.Fatal("unknown processor cannot activate CRS raw-body inspection")
	}
	if !secRawPhaseFixture(t, rule, "application/x-www-form-urlencoded", "q=attack").Blocked {
		t.Fatal("URLencoded raw bytes lost")
	}
}
