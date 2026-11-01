package main

import (
	"strings"
	"testing"
)

func TestSecSelectorsLiteralNamesIgnoreCaseForEveryCollection(t *testing.T) {
	for _, target := range []string{"ARGS:token", "REQUEST_COOKIES:token", "ARGS_POST:token"} {
		collection, _, _ := strings.Cut(target, ":")
		rules, err := parseSecLang("selector.conf", `SecRule `+target+` "@contains attack" "id:2710,phase:2,deny"`)
		if err != nil {
			t.Fatal(err)
		}
		got, err := evaluateSecLang(rules, map[string][]string{collection + ":ToKeN": {"attack"}}, 5)
		if err != nil || !got.Blocked {
			t.Fatalf("%s: %+v %v", target, got, err)
		}
		rules[0].Targets = collection + "|!" + target
		got, err = evaluateSecLang(rules, map[string][]string{collection + ":ToKeN": {"attack"}, collection + ":other": {"safe"}}, 5)
		if err != nil || got.Blocked {
			t.Fatalf("excluded %s: %+v %v", target, got, err)
		}
	}
}
func TestSecSelectorsRegexAlternationExclusionAndCounts(t *testing.T) {
	if !secRegexAvailable() {
		t.Skip("PCRE2 runtime required")
	}
	for _, tc := range []struct {
		target string
		want   bool
	}{
		{`ARGS:/^(foo|bar)$/`, true},
		{`ARGS|!ARGS:/^(foo|bar)$/`, false},
		{`&ARGS:/^(foo|bar)$/`, false},
	} {
		rules, err := parseSecLang("selector.conf", `SecRule `+tc.target+` "@contains attack" "id:2711,phase:2,deny"`)
		if err != nil {
			t.Fatal(err)
		}
		got, err := evaluateSecLang(rules, map[string][]string{"ARGS:FOO": {"attack"}, "ARGS:bar": {"attack"}, "ARGS:other": {"safe"}}, 5)
		if err != nil || got.Blocked != tc.want {
			t.Fatalf("%s: %+v %v", tc.target, got, err)
		}
	}
	rules, err := parseSecLang("count.conf", `SecRule &ARGS:/^(foo|bar)$/ "@eq 3" "id:2712,phase:2,deny"`)
	if err != nil {
		t.Fatal(err)
	}
	got, err := evaluateSecLang(rules, map[string][]string{"ARGS:FOO": {"one", "two"}, "ARGS:bar": {"three"}}, 5)
	if err != nil || !got.Blocked {
		t.Fatalf("count: %+v %v", got, err)
	}
	for _, target := range []string{`ARGS:/unterminated`, `ARGS:/[/`, `ARGS:/foo/x`} {
		rules[0].Targets = target
		if secLangCompatibility(rules).Publishable {
			t.Fatalf("invalid selector accepted: %s", target)
		}
	}
}
func TestSecSelectorsRegexBudgetFailureIsIncomplete(t *testing.T) {
	if !secRegexAvailable() {
		t.Skip("PCRE2 runtime required")
	}
	rules, err := parseSecLang("budget.conf", `SecRule ARGS:/^(a+)+$/ "@contains attack" "id:2713,phase:2,deny"`)
	if err != nil {
		t.Fatal(err)
	}
	_, err = evaluateSecLang(rules, map[string][]string{"ARGS:" + strings.Repeat("a", 10000) + "!": {"attack"}}, 5)
	if err == nil {
		t.Fatal("selector budget failure reported clean")
	}
}

func TestSecNameCollectionSelectorsAddressOriginalNames(t *testing.T) {
	rules, err := parseSecLang("names.conf", `SecRule ARGS_NAMES|!ARGS_NAMES:json.profile "@contains profile" "id:2714,phase:2,deny"`)
	if err != nil {
		t.Fatal(err)
	}
	got, err := evaluateSecLang(rules, map[string][]string{"ARGS_NAMES": {"json.profile", "ordinary"}}, 5)
	if err != nil || got.Blocked {
		t.Fatalf("name exclusion ignored: %+v %v", got, err)
	}
	rules[0].Targets = "ARGS_NAMES:json.profile"
	got, err = evaluateSecLang(rules, map[string][]string{"ARGS_NAMES": {"json.profile", "ordinary"}}, 5)
	if err != nil || !got.Blocked {
		t.Fatalf("explicit name selection missed: %+v %v", got, err)
	}
}
