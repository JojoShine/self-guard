package main

import (
	"sync"
	"testing"
)

func TestPreparedSecLangPlanIsImmutableAndRequestStateDoesNotLeak(t *testing.T) {
	source := `SecRule ARGS:q "@contains attack" "id:1001,phase:2,deny,setvar:'tx.request_hit=1'"`
	rules, err := parseSecLang("plan.conf", source)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := prepareSecLangPlan(rules)
	if err != nil {
		t.Fatal(err)
	}
	rules[0].Targets = "ARGS:unrelated"
	rules[0].Actions["deny"] = nil
	rules[0].ActionOrder = nil
	var workers sync.WaitGroup
	for i := 0; i < 8; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for n := 0; n < 10; n++ {
				hit, e := evaluateSecLangPlan(plan, map[string][]string{"ARGS:q": {"attack"}}, 5)
				if e != nil || !hit.Blocked || hit.Variables["request_hit"] != "1" {
					t.Errorf("immutable plan changed: %+v %v", hit, e)
				}
				clean, e := evaluateSecLangPlan(plan, map[string][]string{"ARGS:q": {"benign"}}, 5)
				if e != nil || clean.Blocked || clean.Variables["request_hit"] != "" {
					t.Errorf("transaction state leaked: %+v %v", clean, e)
				}
			}
		}()
	}
	workers.Wait()
}
func TestPreparedSecLangPlanKeepsStaticTargetUpdatesAndRejectsUnsupportedSemantics(t *testing.T) {
	rules, err := parseSecLang("targets.conf", `SecRule ARGS "@contains attack" "id:1001,phase:2,deny"
SecRuleUpdateTargetById 1001 "!ARGS:excluded"`)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := prepareSecLangPlan(rules)
	if err != nil {
		t.Fatal(err)
	}
	for n := 0; n < 3; n++ {
		result, e := evaluateSecLangPlan(plan, map[string][]string{"ARGS:excluded": {"attack"}}, 5)
		if e != nil || result.Blocked {
			t.Fatalf("static targets changed across requests: %+v %v", result, e)
		}
	}
	unsupported, _ := parseSecLang("unsupported.conf", `SecRule ARGS "@unknown payload" "id:1002,phase:2,deny"`)
	if _, err = prepareSecLangPlan(unsupported); err == nil {
		t.Fatal("unsupported plan accepted")
	}
}
