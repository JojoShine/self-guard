package main

import "testing"

func TestSecLangBlockStatusBelongsToMatchedRootAndNonBlockingRulesDoNotChangeResponse(t *testing.T) {
	for _, tc := range []struct {
		source  string
		blocked bool
		status  int
	}{{`SecRule ARGS:q "@contains attack" "id:1,phase:2,deny"`, true, 403}, {`SecRule ARGS:q "@contains attack" "id:1,phase:2,deny,status:451"`, true, 451}, {`SecRule ARGS:q "@contains attack" "id:1,phase:2,deny,status:400,chain"
SecRule ARGS:r "@streq confirmed"`, true, 400}, {`SecRule ARGS:q "@contains attack" "id:1,phase:2,pass,status:500"`, false, 0}} {
		rules, err := parseSecLang("status.conf", tc.source)
		if err != nil {
			t.Fatal(err)
		}
		result, err := evaluateSecLang(rules, map[string][]string{"ARGS:q": {"attack"}, "ARGS:r": {"confirmed"}}, 5)
		if err != nil || result.Blocked != tc.blocked || result.Status != tc.status {
			t.Fatalf("%+v %v", result, err)
		}
	}
}
func TestSecLangCompatibilityRejectsInvalidOrAmbiguousBlockStatuses(t *testing.T) {
	for _, status := range []string{"status:invalid", "status:999", "status:403,status:451", "status:100"} {
		rules, err := parseSecLang("invalid-status.conf", `SecRule ARGS:q "@contains attack" "id:1,phase:2,deny,`+status+`"`)
		if err == nil && secLangCompatibility(rules).Publishable {
			t.Fatalf("invalid blocking status accepted: %s", status)
		}
	}
}
