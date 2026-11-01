package main

import (
	"strings"
	"testing"
)

func TestSecLangMatchedVariablesAndMacrosUseActualOperatorMatches(t *testing.T) {
	source := `SecRule ARGS "@contains attack" "id:2730,phase:2,pass,t:lowercase,setvar:'tx.name=%{matched_var_name}',setvar:'tx.value=%{matched_var}',chain"
SecRule MATCHED_VARS "@streq attack-two" "chain"
SecRule MATCHED_VAR_NAME "@streq MATCHED_VARS:ARGS:b" "setvar:'tx.inbound_anomaly_score_pl1=+5'"
SecRule TX:name "@streq ARGS:b" "id:2731,phase:2,deny"`
	rules, err := parseSecLang("matches.conf", source)
	if err != nil {
		t.Fatal(err)
	}
	got, err := evaluateSecLang(rules, map[string][]string{"ARGS:a": {"ATTACK-one"}, "ARGS:b": {"ATTACK-two"}}, 5)
	if err != nil || !got.Blocked || got.Score != 5 || got.Variables["name"] != "ARGS:b" || got.Variables["value"] != "attack-two" {
		t.Fatalf("%+v %v", got, err)
	}
}
func TestSecLangRequestMacrosAndDynamicTransactionNamesAreBounded(t *testing.T) {
	rules, err := parseSecLang("macro.conf", `SecRule ARGS:q "@streq %{request_headers.host}" "id:2732,phase:2,pass,setvar:'tx.seen-%{matched_var_name}=%{remote_addr}'"
SecRule TX:seen-ARGS:q "@streq 192.0.2.1" "id:2733,phase:2,deny"`)
	if err != nil {
		t.Fatal(err)
	}
	got, err := evaluateSecLang(rules, map[string][]string{"ARGS:q": {"example.test"}, "REQUEST_HEADERS:Host": {"example.test"}, "REMOTE_ADDR": {"192.0.2.1"}}, 5)
	if err != nil || !got.Blocked {
		t.Fatalf("%+v %v", got, err)
	}
	rules[0].Actions["setvar"] = []string{"tx.%{unknown}=1"}
	rules[0].ActionOrder = []secAction{{"setvar", "tx.%{unknown}=1"}}
	if secLangCompatibility(rules).Publishable {
		t.Fatal("unknown dynamic name macro accepted")
	}
}
func TestSecLangUnmatchedRuleDoesNotInventMatchFromRequestVariables(t *testing.T) {
	rules, err := parseSecLang("matches.conf", `SecRule MATCHED_VAR "@contains forged" "id:2734,phase:1,deny"`)
	if err != nil {
		t.Fatal(err)
	}
	got, err := evaluateSecLang(rules, map[string][]string{"MATCHED_VAR": {"forged"}}, 5)
	if err != nil || got.Blocked {
		t.Fatalf("caller supplied reserved transaction state: %+v %v", got, err)
	}
}

func TestSecLangAuditSwitchIsTransactionLocalAndDoesNotSkipDetection(t *testing.T) {
	rules, err := parseSecLang("audit.conf", `SecAction "id:2840,phase:1,pass,ctl:auditEngine=Off"
SecRule ARGS "@contains attack" "id:2841,phase:2,deny"`)
	if err != nil {
		t.Fatal(err)
	}
	result, err := evaluateSecLang(rules, map[string][]string{"ARGS:q": {"attack"}}, 5)
	if err != nil || !result.Blocked || result.AuditEnabled {
		t.Fatalf("audit switch affected detection: %+v %v", result, err)
	}
	result, err = evaluateSecLang(rules[1:], map[string][]string{"ARGS:q": {"attack"}}, 5)
	if err != nil || !result.Blocked || !result.AuditEnabled {
		t.Fatalf("audit state leaked to another transaction: %+v %v", result, err)
	}
}
func TestSecTransactionBudgetsRejectGrowthWithoutChangingPriorState(t *testing.T) {
	frame := secTransaction{}
	tx := map[string]string{}
	value := strings.Repeat("x", 1<<20)
	for _, name := range []string{"first", "second", "third"} {
		if err := frame.setTX(tx, name, value); err != nil {
			t.Fatal(err)
		}
	}
	if err := frame.setTX(tx, "fourth", value); err == nil {
		t.Fatal("transaction byte cap missing")
	}
	if _, exists := tx["fourth"]; exists {
		t.Fatal("over-budget value committed")
	}
	frame.deleteTX(tx, "first")
	if err := frame.setTX(tx, "fourth", value); err != nil {
		t.Fatal("deleted state did not release budget", err)
	}
	for i := 0; i < 3; i++ {
		if err := frame.record("ARGS:q", value); err != nil {
			t.Fatal(err)
		}
	}
	if err := frame.record("ARGS:q", value); err == nil {
		t.Fatal("matched-variable byte cap missing")
	}
}
