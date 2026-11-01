//go:build pcre2 && cgo

package main

import (
	"os"
	"strings"
	"sync"
	"testing"
)

func TestBoundedPCRE2LargeLinearRuleAndSmallAttackKeepSeparateWorkBudgets(t *testing.T) {
	source, err := os.ReadFile("testdata/crs942360-budget.conf")
	if err != nil {
		t.Fatal(err)
	}
	rules, err := parseSecLang("crs942360-budget.conf", string(source))
	if err != nil || len(rules) != 1 || rules[0].ID != "942360" {
		t.Fatalf("frozen regression rule: %v %v", rules, err)
	}
	for repeat := 0; repeat < 5; repeat++ {
		ok, groups, err := captureSecRegex(rules[0].Operand, strings.Repeat("1", 1<<20))
		if err != nil || ok || len(groups) != 0 {
			t.Fatalf("bounded linear nonmatch was incomplete: %v %v", ok, err)
		}
		if _, err = matchSecRegex(`^(a+)+$`, strings.Repeat("a", 18)+"!"); err == nil {
			t.Fatal("large input budget leaked into a small backtracking attack")
		}
	}
	if _, err = matchSecRegex(rules[0].Operand, strings.Repeat("1", (1<<20)+1)); err == nil {
		t.Fatal("regex subject size limit removed")
	}
}

func TestSecLangCapturesAreAvailableInsideChainAndDoNotLeak(t *testing.T) {
	for _, x := range []struct {
		source   string
		input    map[string][]string
		blocked  bool
		captured string
	}{
		{`SecRule ARGS:q "@rx (?i)^([a-z]+):([a-z]+)$" "id:2001,phase:2,capture,chain,deny"
SecRule TX:2 "@streq admin" "setvar:'tx.selected=%{tx.1}'"`, map[string][]string{"ARGS:q": {"user:admin"}}, true, "user"},
		{`SecRule ARGS:q "@rx ^(a)(b)$" "id:2001,phase:2,capture,pass"
SecRule ARGS:r "@rx ^(c)$" "id:2002,phase:2,capture,pass"
SecRule &TX:2 "@eq 0" "id:2003,phase:2,deny"`, map[string][]string{"ARGS:q": {"ab"}, "ARGS:r": {"c"}}, true, ""},
		{`SecRule ARGS:q "@pm select union" "id:2001,phase:2,capture,chain,deny"
SecRule TX:0 "@streq union"`, map[string][]string{"ARGS:q": {"union benign"}}, true, ""},
	} {
		rules, err := parseSecLang("capture.conf", x.source)
		if err != nil {
			t.Fatal(err)
		}
		result, err := evaluateSecLang(rules, x.input, 5)
		if err != nil || result.Blocked != x.blocked || result.Variables["selected"] != x.captured {
			t.Fatalf("%+v %v", result, err)
		}
		clean, err := evaluateSecLang(rules, map[string][]string{}, 5)
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := clean.Variables["1"]; ok {
			t.Fatal("request capture leaked")
		}
	}
}

func TestBoundedPCRE2SupportsLookaroundAndBackreferences(t *testing.T) {
	for _, x := range []struct {
		pattern, value string
		want           bool
	}{{`(?i)(?<=union\s)select`, `UNION SELECT`, true}, {`(['"]).*?\1`, `'value'`, true}, {`^safe$`, `unsafe`, false}} {
		actual, err := matchSecRegex(x.pattern, x.value)
		if err != nil || actual != x.want {
			t.Fatalf("%q %q: %v %v", x.pattern, x.value, actual, err)
		}
	}
	if _, err := matchSecRegex(`([`, "input"); err == nil {
		t.Fatal("invalid expression accepted")
	}
	if _, err := matchSecRegex(`^(a+)+$`, string(makeRepeatedSecBytes('a', 30000))+"!"); err == nil {
		t.Fatal("resource limit not enforced")
	}
}
func makeRepeatedSecBytes(value byte, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = value
	}
	return b
}

func TestSecLangBudgetDiagnosticIdentifiesRootRuleWithoutRequestContents(t *testing.T) {
	for _, capture := range []string{"", ",capture"} {
		rules, err := parseSecLang("budget-context.conf", `SecRule ARGS:marker "@contains private-marker" "id:2880,phase:2,chain,deny"
SecRule ARGS:q "@rx ^(a+)+$" "t:none`+capture+`"`)
		if err != nil {
			t.Fatal(err)
		}
		_, err = evaluateSecLang(rules, map[string][]string{"ARGS:marker": {"private-marker"}, "ARGS:q": {strings.Repeat("a", 30000) + "!"}}, 5)
		if err == nil || !strings.HasPrefix(err.Error(), "PCRE2 compilation or execution budget failure") || !strings.Contains(err.Error(), "[rule 2880]") || strings.Contains(err.Error(), "private-marker") || strings.Contains(err.Error(), "aaaa") {
			t.Fatalf("missing bounded private rule diagnostic: %v", err)
		}
	}
}

func TestSecLangCaptureFollowsOperatorBeforeNegationAndNoopActionsPreserveIt(t *testing.T) {
	for _, tc := range []struct{ operator, value, want string }{
		{"!@rx ^(new)$", "new", "new"}, {"!@rx ^(new)$", "other", "secret"},
		{"@contains other", "other", "secret"}, {"@streq other", "other", "secret"},
	} {
		source := `SecRule ARGS:q "@rx ^(secret)$" "id:2800,phase:2,pass,capture"` + "\n" + `SecRule ARGS:r "` + tc.operator + `" "id:2801,phase:2,pass,capture"` + "\n" + `SecRule TX:1 "@streq ` + tc.want + `" "id:2802,phase:2,deny"`
		rules, err := parseSecLang("negated-capture.conf", source)
		if err != nil {
			t.Fatal(err)
		}
		got, err := evaluateSecLang(rules, map[string][]string{"ARGS:q": {"secret"}, "ARGS:r": {tc.value}}, 5)
		if err != nil || !got.Blocked {
			t.Fatalf("%+v: %+v %v", tc, got, err)
		}
	}
	rules, err := parseSecLang("xss-capture.conf", `SecRule ARGS:q "@detectXSS" "id:2803,phase:2,capture,pass"
SecRule TX:0 "@contains onload" "id:2804,phase:2,deny"`)
	if err != nil {
		t.Fatal(err)
	}
	got, err := evaluateSecLang(rules, map[string][]string{"ARGS:q": {"<svg/onload=alert(1)>"}}, 5)
	if err != nil || !got.Blocked {
		t.Fatalf("XSS capture: %+v %v", got, err)
	}
}

func TestBooleanPCREChecksAgreeWithCaptureChecksAcrossFailuresAndGroups(t *testing.T) {
	for _, row := range []struct{ pattern, subject string }{{`(?i)^([a-z]+):([0-9]+)$`, `User:42`}, {`(?<=prefix)\w+`, `prefixValue`}, {`(a)?(b)`, `b`}, {`^$`, ``}, {`\x00`, string([]byte{'a', 0, 'b'})}, {`(界)+`, `界界`}, {`^safe$`, `unsafe`}, {`([`, `invalid`}, {`^(a+)+$`, string(makeRepeatedSecBytes('a', 30000)) + "!"}} {
		expected, _, captureError := captureSecRegex(row.pattern, row.subject)
		actual, booleanError := matchSecRegex(row.pattern, row.subject)
		if actual != expected || (captureError == nil) != (booleanError == nil) {
			t.Fatalf("boolean result differs for %q: %v/%v vs %v/%v", row.pattern, actual, booleanError, expected, captureError)
		}
	}
}

func TestPCREExecutionContextReuseKeepsCaptureBoundsAndConcurrentOwnership(t *testing.T) {
	var workers sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for iteration := 0; iteration < 30; iteration++ {
				ok, groups, err := captureSecRegex(strings.Repeat("(a)", 110), strings.Repeat("a", 110))
				if err != nil || !ok || len(groups) != 100 || groups["99"] != "a" {
					t.Errorf("capture cap or context ownership failed: count=%d err=%v", len(groups), err)
					return
				}
				if ok, err := matchSecRegex("^plain$", "plain"); err != nil || !ok {
					t.Error("boolean reuse failed", err)
					return
				}
				ok, groups, err = captureSecRegex("^(a)?(b)$", "b")
				if err != nil || !ok || len(groups) != 2 || groups["0"] != "b" || groups["2"] != "b" {
					t.Errorf("stale capture survived context reuse: %+v %v", groups, err)
					return
				}
			}
		}()
	}
	workers.Wait()
}
