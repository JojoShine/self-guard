package main

import "testing"

const secCollectionFixture = `SecRule ARGS:enforce "@eq 1" "id:2830,phase:1,pass,setvar:'tx.visited=1',chain"
SecRule TX:enable_default_collections "@eq 1" "chain"
SecRule TX:visited "@unconditionalMatch" "initcol:global=global"`

func TestSecLangFixedProfileOnlyPrunesProvenDisabledCollectionTail(t *testing.T) {
	rules, err := parseSecLang("profile.conf", secCollectionFixture)
	if err != nil {
		t.Fatal(err)
	}
	report := secLangCompatibility(rules)
	if !report.Publishable || report.InactiveByConfiguration != 2 {
		t.Fatalf("disabled optional tail not explained: %+v", report)
	}
	got, err := evaluateSecLang(rules, map[string][]string{"ARGS:enforce": {"1"}}, 5)
	if err != nil || got.Variables["visited"] != "1" || len(got.Matches) != 0 {
		t.Fatalf("pruning changed earlier chain effects: %+v %v", got, err)
	}
	for _, assignment := range []string{"tx.enable_default_collections=1", "tx.%{tx.name}=1"} {
		changed, err := parseSecLang("enabled.conf", `SecAction "id:2831,phase:1,pass,setvar:'`+assignment+`'"`+"\n"+secCollectionFixture)
		if err != nil {
			t.Fatal(err)
		}
		if secLangCompatibility(changed).Publishable {
			t.Fatalf("unknown/enabled persistent collection silently accepted: %s", assignment)
		}
	}
	unguarded, err := parseSecLang("unguarded.conf", `SecAction "id:2832,phase:1,pass,initcol:global=global"`)
	if err != nil {
		t.Fatal(err)
	}
	if secLangCompatibility(unguarded).Publishable {
		t.Fatal("active unsupported initcol accepted")
	}
}
func TestSecLangRequestFixturesCannotForgeTransactionConfiguration(t *testing.T) {
	rules, err := parseSecLang("profile.conf", secCollectionFixture)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = evaluateSecLang(rules, map[string][]string{"TX:ENABLE_DEFAULT_COLLECTIONS": {"1"}, "ARGS:enforce": {"1"}}, 5); err == nil {
		t.Fatal("request injected engine transaction state")
	}
}
