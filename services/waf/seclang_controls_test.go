package main

import "testing"

func TestSecLangRuntimeTagExclusionsAreConditionalAndTransactionLocal(t *testing.T) {
	if !secRegexAvailable() {
		t.Skip("PCRE2 required")
	}
	source := `SecRule ARGS:exclude "@streq yes" "id:2770,phase:1,pass,ctl:ruleRemoveTargetByTag=attack-sqli;ARGS:token"
SecRule ARGS "@contains attack" "id:2771,phase:2,deny,tag:attack-sqli"
SecRule ARGS:other "@contains attack" "id:2772,phase:2,deny,tag:attack-xss"`
	rules, err := parseSecLang("ctl.conf", source)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		exclude, other string
		blocked        bool
	}{{"yes", "safe", false}, {"no", "safe", true}, {"yes", "attack", true}, {"yes", "safe", false}} {
		got, err := evaluateSecLang(rules, map[string][]string{"ARGS:exclude": {tc.exclude}, "ARGS:token": {"attack"}, "ARGS:other": {tc.other}}, 5)
		if err != nil || got.Blocked != tc.blocked {
			t.Fatalf("%+v: %+v %v", tc, got, err)
		}
	}
}
func TestSecLangRuntimeTagRemovalAndUnknownControlGate(t *testing.T) {
	if !secRegexAvailable() {
		t.Skip("PCRE2 required")
	}
	rules, err := parseSecLang("ctl.conf", `SecAction "id:2773,phase:1,pass,ctl:ruleRemoveByTag=^OWASP_CRS$"
SecRule ARGS "@contains attack" "id:2774,phase:2,deny,tag:OWASP_CRS"
SecRule ARGS "@contains other" "id:2775,phase:2,deny,tag:custom"`)
	if err != nil {
		t.Fatal(err)
	}
	got, err := evaluateSecLang(rules, map[string][]string{"ARGS:q": {"attack"}}, 5)
	if err != nil || got.Blocked {
		t.Fatalf("%+v %v", got, err)
	}
	got, err = evaluateSecLang(rules, map[string][]string{"ARGS:q": {"other"}}, 5)
	if err != nil || !got.Blocked {
		t.Fatalf("custom rule lost: %+v %v", got, err)
	}
	for _, value := range []string{"ruleEngine=Off", "ruleRemoveTargetByTag=tag", "ruleRemoveTargetByTag=tag;UNKNOWN:q", "ruleRemoveByTag=[", "ruleRemoveByTag=%{tx.tag}"} {
		rules[0].Actions["ctl"] = []string{value}
		rules[0].ActionOrder = []secAction{{"ctl", value}}
		if secLangCompatibility(rules).Publishable {
			t.Fatalf("unsupported control accepted: %s", value)
		}
	}
}
