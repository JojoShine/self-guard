package main

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"testing"
)

func TestSecLangParsesContinuationQuotedActionsAndChains(t *testing.T) {
	source := `SecRule ARGS:q "@contains union" \
 "id:1001,phase:2,deny,t:none,t:lowercase,msg:'SQL, sample',chain"
SecRule ARGS:q "@contains select" "t:none,t:lowercase,setvar:'tx.inbound_anomaly_score_pl1=+5'"
SecMarker END-TEST
`
	rules, err := parseSecLang("test.conf", source)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 2 || rules[0].ID != "1001" || len(rules[0].Chain) != 1 || rules[0].Actions["msg"][0] != "SQL, sample" {
		t.Fatalf("%+v", rules)
	}
	result, err := evaluateSecLang(rules, map[string][]string{"ARGS:q": {"UNION SELECT password"}}, 5)
	if err != nil || !result.Blocked || result.Score != 5 || len(result.Matches) != 1 {
		t.Fatalf("%+v %v", result, err)
	}
	safe, err := evaluateSecLang(rules, map[string][]string{"ARGS:q": {"union benign"}}, 5)
	if err != nil || safe.Blocked || safe.Score != 0 || len(safe.Matches) != 0 {
		t.Fatalf("chain partial match applied actions: %+v %v", safe, err)
	}
}
func TestSecLangPhrasesIgnoreASCIICaseAndCaptureFirstEncounteredMatch(t *testing.T) {
	ok, err := matchSecOperator("pm", "select union", "UNION benign")
	if err != nil || !ok {
		t.Fatal("case-insensitive phrase missed", err)
	}
	rules, err := parseSecLang("phrases.conf", `SecRule ARGS:q "@pm select union" "id:2010,phase:2,capture,chain,deny"
SecRule TX:0 "@streq union" "t:lowercase"`)
	if err != nil {
		t.Fatal(err)
	}
	result, err := evaluateSecLang(rules, map[string][]string{"ARGS:q": {"UNION then select"}}, 5)
	if err != nil || !result.Blocked {
		t.Fatalf("%+v %v", result, err)
	}
	bad, err := parseSecLang("macro.conf", `SecRule ARGS:q "@pm %{tx.phrases}" "id:2011,phase:2,deny"`)
	if err != nil {
		t.Fatal(err)
	}
	if secLangCompatibility(bad).Publishable {
		t.Fatal("unsupported phrase macros silently expanded")
	}
}
func TestSecLangNumericOperatorsUseIntegerSemanticsWithoutFloatRounding(t *testing.T) {
	for _, x := range []struct {
		operator, operand, value string
		want                     bool
	}{
		{"eq", "9007199254740992", "9007199254740993", false},
		{"gt", "9007199254740992", "9007199254740993", true},
		{"eq", "0", "not a number", true},
		{"eq", "12", "  +12suffix", true},
		{"eq", "1", "1.9", true},
	} {
		got, err := matchSecOperator(x.operator, x.operand, x.value)
		if err != nil || got != x.want {
			t.Fatalf("%+v got %v %v", x, got, err)
		}
	}
}
func TestSecLangUnknownSemanticsAndMalformedRulesBlockPublication(t *testing.T) {
	for _, source := range []string{`SecRule ARGS "@exec /bin/sh" "id:1001,phase:2,deny"`, `SecRule ARGS "@contains test" "id:1001,phase:2,exec:/bin/sh"`, `SecRule ARGS "@contains test" "id:1001,phase:2,t:unknown"`} {
		rules, err := parseSecLang("rules.conf", source)
		if err != nil {
			t.Fatal(err)
		}
		report := secLangCompatibility(rules)
		if report.Publishable || len(report.Unsupported) == 0 {
			t.Fatalf("%+v", report)
		}
	}
	for _, source := range []string{`SecRule ARGS "@contains test" "id:1001,chain"`, `SecRule ARGS "unterminated`, "SecRule ARGS \"@contains test\" \"id:1\"\nSecRule ARGS \"@contains test\" \"id:1\""} {
		if _, err := parseSecLang("rules.conf", source); err == nil {
			t.Fatal("invalid rules accepted")
		}
	}
}
func TestSecLangTxScoringSkipMarkersAndExactTransforms(t *testing.T) {
	source := `SecAction "id:1000,phase:1,pass,setvar:'tx.threshold=5'"
SecRule ARGS:q "@contains <script" "id:1001,phase:2,t:none,t:urlDecodeUni,t:lowercase,setvar:'tx.score=+5'"
SecRule TX:score "@ge %{tx.threshold}" "id:1002,phase:2,deny"
`
	rules, err := parseSecLang("rules.conf", source)
	if err != nil {
		t.Fatal(err)
	}
	result, err := evaluateSecLang(rules, map[string][]string{"ARGS:q": {"%3CScRiPt>"}}, 5)
	if err != nil || !result.Blocked || result.Variables["score"] != "5" {
		t.Fatalf("%+v %v", result, err)
	}
	report := secLangCompatibility(rules)
	if !report.Publishable {
		t.Fatalf("supported native fixture not publishable: %+v", report)
	}
	if _, err := parseSecLang("too-large.conf", strings.Repeat(" ", 4<<20)); err == nil {
		t.Fatal("unbounded source accepted")
	}
}

func TestSecLangUnicodeUrlDecodeAndMalformedSequences(t *testing.T) {
	for input, want := range map[string]string{"%uFF53%u0065lect": "select", "%u1234": "4", "a%2Bb+c": "a+b c", "%zz%uXYZ": "%zz%uXYZ", "%252f": "%2f"} {
		got, err := transformSecValue(input, []string{"urlDecodeUni"})
		if err != nil || got != want {
			t.Fatalf("%q got %q want %q (%v)", input, got, want, err)
		}
	}
}
func TestSecLangCollectionExclusionRemovesOnlyNamedParameters(t *testing.T) {
	rules, err := parseSecLang("exclusion.conf", `SecRule ARGS|!ARGS:token "@contains attack" "id:1001,phase:2,deny"`)
	if err != nil {
		t.Fatal(err)
	}
	result, err := evaluateSecLang(rules, map[string][]string{"ARGS:token": {"attack"}, "ARGS:q": {"safe"}}, 5)
	if err != nil || result.Blocked {
		t.Fatalf("excluded variable checked: %+v %v", result, err)
	}
}
func TestSecLangHeadersIgnoreNameCaseAndTransactionExclusionsApply(t *testing.T) {
	for _, source := range []string{
		`SecRule REQUEST_HEADERS:content-type "@contains attack" "id:2601,phase:2,deny"`,
		`SecRule REQUEST_HEADERS|!REQUEST_HEADERS:content-type "@contains attack" "id:2601,phase:2,deny"`,
	} {
		rules, err := parseSecLang("header.conf", source)
		if err != nil {
			t.Fatal(err)
		}
		result, err := evaluateSecLang(rules, map[string][]string{"REQUEST_HEADERS:Content-Type": {"attack"}}, 5)
		want := !strings.Contains(source, "!")
		if err != nil || result.Blocked != want {
			t.Fatalf("%s: %+v %v", source, result, err)
		}
	}
	values, err := secRuleVariables("TX|!TX:secret", map[string][]string{}, map[string]string{"secret": "attack", "ordinary": "safe"})
	if err != nil || len(values) != 1 || values[0].value != "safe" {
		t.Fatalf("TX exclusion failed: %q", values)
	}
}

func TestSecLangChainedConditionMayOmitActions(t *testing.T) {
	rules, err := parseSecLang("chain.conf", "SecRule ARGS:q \"@contains attack\" \"id:1001,phase:2,chain,deny\"\nSecRule ARGS:q \"@contains payload\"")
	if err != nil {
		t.Fatal(err)
	}
	result, err := evaluateSecLang(rules, map[string][]string{"ARGS:q": {"attack payload"}}, 5)
	if err != nil || !result.Blocked {
		t.Fatalf("%+v %v", result, err)
	}
}

func TestSecLangValidationOperatorsHaveAttackAndBenignBoundaries(t *testing.T) {
	cases := []struct {
		operator, operand, value string
		want                     bool
	}{
		{"pm", "union select", "select password", true}, {"pm", "union select", "normal request", false},
		{"ipmatch", "192.0.2.0/24,2001:db8::/32", "192.0.2.42", true}, {"ipmatch", "192.0.2.0/24,2001:db8::/32", "2001:db8::2", true}, {"ipmatch", "192.0.2.0/24", "198.51.100.2", false},
		{"validatebyterange", "9,10,13,32-126", "normal\nrequest", false}, {"validatebyterange", "1-255", "zero\x00byte", true},
		{"validateurlencoding", "", "%41+normal", false}, {"validateurlencoding", "", "%zz", true}, {"validateurlencoding", "", "trailing%", true},
		{"validateutf8encoding", "", "正常文本", false}, {"validateutf8encoding", "", string([]byte{0xc0, 0xaf}), true},
	}
	for _, c := range cases {
		got, err := matchSecOperator(c.operator, c.operand, c.value)
		if err != nil || got != c.want {
			t.Fatalf("%s %q: got %v want %v (%v)", c.operator, c.value, got, c.want, err)
		}
	}
	if _, err := matchSecOperator("ipmatch", "invalid-cidr", "192.0.2.1"); err == nil {
		t.Fatal("invalid configured CIDR accepted")
	}
	if _, err := matchSecOperator("validatebyterange", "256-300", "input"); err == nil {
		t.Fatal("invalid byte range accepted")
	}
}
func TestSecLangByteTransformsPreserveNonASCIIAndUseDeclaredWhitespace(t *testing.T) {
	for _, c := range []struct {
		input      string
		transforms []string
		want       string
	}{
		{"HELLO É 世界", []string{"lowercase"}, "hello É 世界"},
		{"a\t \r\nb", []string{"compressWhitespace"}, "a b"},
		{"a \t\n世界", []string{"removeWhitespace"}, "a世界"},
		{"a\x00", []string{"hexEncode"}, "6100"},
	} {
		got, err := transformSecValue(c.input, c.transforms)
		if err != nil || got != c.want {
			t.Fatalf("%q: %q != %q (%v)", c.input, got, c.want, err)
		}
	}
}

func TestSecLangCompatibilityRejectsInvalidOperandsAndUnsupportedMacros(t *testing.T) {
	for _, source := range []string{`SecRule REMOTE_ADDR "@ipMatch invalid-cidr" "id:1001,phase:2,deny"`, `SecRule ARGS:q "@validateByteRange 300-400" "id:1001,phase:2,deny"`, `SecRule ARGS:q "@contains %{rule.unknown}" "id:1001,phase:2,deny"`, `SecAction "id:1001,phase:1,setvar:'tx.%{unknown.name}=5'"`} {
		rules, err := parseSecLang("invalid.conf", source)
		if err != nil {
			t.Fatal(err)
		}
		report := secLangCompatibility(rules)
		if report.Publishable {
			t.Fatalf("invalid operand or macro passed: %s", source)
		}
	}
}

func TestSecLangHTMLAndWhitespaceFollowByteSemantics(t *testing.T) {
	for _, c := range []struct{ input, want string }{{"&#x263a;", ":"}, {"&#0;", "\x00"}, {"&lt;script&gt;", "<script>"}, {"&amp;quot;", "&quot;"}, {"&colon;", "&colon;"}} {
		got, err := transformSecValue(c.input, []string{"htmlEntityDecode"})
		if err != nil || got != c.want {
			t.Fatalf("%q -> %q want %q (%v)", c.input, got, c.want, err)
		}
	}
	if got, err := transformSecValue("a\xa0\tb", []string{"compressWhitespace"}); err != nil || got != "a b" {
		t.Fatalf("NBSP compression: %q %v", got, err)
	}
}
func TestSecLangCommentAndPathNormalization(t *testing.T) {
	cases := []struct{ input, transform, want string }{
		{"a/*one*//*two*/b", "replaceComments", "a  b"}, {"a/*unfinished", "replaceComments", "a "}, {"a*/b", "replaceComments", "a*/b"},
		{"a/*b*/--#c", "removeCommentsChar", "abc"},
		{"a//./b/../c/", "normalizePath", "a/c/"}, {"../../a/../b", "normalizePath", "../../b"}, {"/../../etc/passwd", "normalizePath", "/../../etc/passwd"}, {`a\b\..\c`, "normalizePathWin", "a/c"},
		{`C^M\D , /c ; "whoami"`, "cmdLine", "cmd/c whoami"},
	}
	for _, c := range cases {
		got, err := transformSecValue(c.input, []string{c.transform})
		if err != nil || got != c.want {
			t.Fatalf("%s %q -> %q want %q (%v)", c.transform, c.input, got, c.want, err)
		}
	}
}

func TestSecLangPhraseFilesPreservePhrasesAndRejectUncontrolledPaths(t *testing.T) {
	files := []secLangFile{{Name: "rules/custom.conf", Source: `SecRule ARGS:q "@pmFromFile phrases.data" "id:1001,phase:2,deny"`}, {Name: "rules/phrases.data", Source: "# explanation\nhello world\nattack\n"}}
	for _, c := range []struct {
		value   string
		blocked bool
	}{{"contains hello world here", true}, {"just hello", false}, {"normal", false}} {
		fixture := secLangFixture{Files: files, Variables: map[string][]string{"ARGS:q": {c.value}}, Threshold: 5}
		input, _ := json.Marshal(fixture)
		var output bytes.Buffer
		if err := runSecLangCLI(bytes.NewReader(input), &output, true); err != nil {
			t.Fatal(err)
		}
		var result secResult
		if err := json.Unmarshal(output.Bytes(), &result); err != nil || result.Blocked != c.blocked {
			t.Fatalf("%q result %+v (%v)", c.value, result, err)
		}
	}
	for _, name := range []string{"../../etc/passwd", "/etc/passwd", "missing.data"} {
		fixture := secLangFixture{Files: []secLangFile{{Name: "rules/custom.conf", Source: `SecRule ARGS:q "@pmFromFile ` + name + `" "id:1001,phase:2,deny"`}}}
		input, _ := json.Marshal(fixture)
		if err := runSecLangCLI(bytes.NewReader(input), io.Discard, false); err == nil {
			t.Fatalf("unresolved or external phrase file accepted: %s", name)
		}
	}
}

func TestSecLangChainRunsNonDisruptiveActionsBeforeNextCondition(t *testing.T) {
	rules, err := parseSecLang("chain-state.conf", `SecRule ARGS:q "@contains attack" "id:1001,phase:2,pass,chain,setvar:'tx.next=ready'"
SecRule TX:next "@streq ready" "setvar:'tx.checked=yes'"`)
	if err != nil {
		t.Fatal(err)
	}
	result, err := evaluateSecLang(rules, map[string][]string{"ARGS:q": {"attack"}}, 5)
	if err != nil || result.Variables["checked"] != "yes" {
		t.Fatalf("%+v %v", result, err)
	}
}
func TestSecLangLastDisruptiveActionAndEarlyDenial(t *testing.T) {
	rules, err := parseSecLang("pass.conf", `SecRule ARGS:q "@contains attack" "id:1001,phase:2,deny,pass"`)
	if err != nil {
		t.Fatal(err)
	}
	result, err := evaluateSecLang(rules, map[string][]string{"ARGS:q": {"attack"}}, 5)
	if err != nil || result.Blocked {
		t.Fatalf("last pass action ignored: %+v %v", result, err)
	}
	rules, err = parseSecLang("deny.conf", `SecRule ARGS:q "@contains attack" "id:1001,phase:1,deny"
SecAction "id:1002,phase:2,pass,setvar:'tx.after=yes'"`)
	if err != nil {
		t.Fatal(err)
	}
	result, err = evaluateSecLang(rules, map[string][]string{"ARGS:q": {"attack"}}, 5)
	if err != nil || !result.Blocked || result.Variables["after"] != "" {
		t.Fatalf("processing continued after deny: %+v %v", result, err)
	}
}
func TestSecLangScoreUsesAggregateWithoutDoubleCounting(t *testing.T) {
	rules, err := parseSecLang("scores.conf", `SecAction "id:1001,phase:1,pass,setvar:'tx.inbound_anomaly_score_pl1=5',setvar:'tx.inbound_anomaly_score=5'"`)
	if err != nil {
		t.Fatal(err)
	}
	result, err := evaluateSecLang(rules, nil, 10)
	if err != nil || result.Score != 5 || result.Blocked {
		t.Fatalf("scores counted twice: %+v %v", result, err)
	}
}

func TestSecLangExpansionDoesNotInterpretCapturedMacroText(t *testing.T) {
	got, err := expandSecValue("%{tx.input}", map[string]string{"input": "%{tx.secret}", "secret": "must-not-expand"})
	if err != nil || got != "%{tx.secret}" {
		t.Fatalf("captured text evaluated as a template: %q %v", got, err)
	}
	_, err = expandSecValue("%{tx.input}%{tx.input}", map[string]string{"input": strings.Repeat("a", 1<<20)})
	if err == nil {
		t.Fatal("expansion budget ignored")
	}
}
func TestSecLangArithmeticRejectsOverflowAndKeepsAssignmentDistinct(t *testing.T) {
	rules, err := parseSecLang("assignment.conf", `SecAction "id:1001,phase:1,pass,setvar:'tx.initial=-5',setvar:'tx.copy=10',setvar:'tx.copy=%{tx.initial}'"`)
	if err != nil {
		t.Fatal(err)
	}
	result, err := evaluateSecLang(rules, nil, 5)
	if err != nil || result.Variables["copy"] != "-5" {
		t.Fatalf("assignment became arithmetic: %+v %v", result, err)
	}
	rules, err = parseSecLang("overflow.conf", `SecAction "id:1001,phase:1,pass,setvar:'tx.inbound_anomaly_score=9223372036854775807',setvar:'tx.inbound_anomaly_score=+1'"`)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = evaluateSecLang(rules, nil, 5); err == nil {
		t.Fatal("overflow became a clean result")
	}
	rules, err = parseSecLang("dynamic-target.conf", `SecRule TX:%{tx.name} "@eq 1" "id:1001,phase:2,deny"`)
	if err != nil {
		t.Fatal(err)
	}
	if secLangCompatibility(rules).Publishable {
		t.Fatal("unimplemented dynamic variable selector passed compatibility")
	}
}

func TestSecLangMultiMatchChecksOriginalAndChangedIntermediateValues(t *testing.T) {
	for _, tc := range []struct {
		value, operand string
		multi, want    bool
	}{
		{"ATTACK", "ATTACK", true, true},
		{"%41TTACK", "ATTACK", true, true},
		{"%41TTACK", "attack", true, true},
		{"%41TTACK", "ATTACK", false, false},
		{"ordinary", "ATTACK", true, false},
	} {
		actions := "id:2720,phase:2,deny,t:none,t:urlDecode,t:lowercase"
		if tc.multi {
			actions += ",multiMatch"
		}
		rules, err := parseSecLang("multi.conf", `SecRule ARGS "@streq `+tc.operand+`" "`+actions+`"`)
		if err != nil {
			t.Fatal(err)
		}
		got, err := evaluateSecLang(rules, map[string][]string{"ARGS:q": {tc.value}}, 5)
		if err != nil || got.Blocked != tc.want {
			t.Fatalf("%+v: %+v %v", tc, got, err)
		}
	}
}

func TestSecLangSkipCountsOnlyRulesInTheSamePhase(t *testing.T) {
	rules, err := parseSecLang("skip.conf", `SecAction "id:2760,phase:1,pass,skip:1"
SecRule ARGS "@contains attack" "id:2761,phase:2,deny"
SecMarker MIDDLE
SecAction "id:2762,phase:1,setvar:'tx.skipped=1'"
SecAction "id:2763,phase:1,setvar:'tx.kept=1'"`)
	if err != nil {
		t.Fatal(err)
	}
	got, err := evaluateSecLang(rules, map[string][]string{"ARGS:q": {"attack"}}, 5)
	if err != nil || !got.Blocked || got.Variables["skipped"] != "" || got.Variables["kept"] != "1" {
		t.Fatalf("%+v %v", got, err)
	}
	for _, value := range []string{"-1", "1.5", "10001", "%{tx.count}"} {
		rules[0].Actions["skip"] = []string{value}
		if secLangCompatibility(rules).Publishable {
			t.Fatalf("invalid skip accepted: %s", value)
		}
	}
}
func TestSecLangUpdateTargetsAppliesOnlyExplicitKnownRuleAndKeepsSourceImmutable(t *testing.T) {
	rules, err := parseSecLang("targets.conf", `SecRule ARGS "@contains attack" "id:2764,phase:2,deny"
SecRuleUpdateTargetById 2764 "!ARGS:token"`)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		key     string
		blocked bool
	}{{"token", false}, {"q", true}} {
		got, err := evaluateSecLang(rules, map[string][]string{"ARGS:" + tc.key: {"attack"}}, 5)
		if err != nil || got.Blocked != tc.blocked {
			t.Fatalf("%s: %+v %v", tc.key, got, err)
		}
	}
	if rules[0].Targets != "ARGS" {
		t.Fatal("compiler mutated immutable source")
	}
	rules[1].Operand = "99999"
	if secLangCompatibility(rules).Publishable {
		t.Fatal("missing rule target update silently ignored")
	}
}

func TestSecLangFileExecutionOrderMatchesCanonicalBundleDigest(t *testing.T) {
	first := secLangFile{Name: "rules/100-init.conf", Source: `SecAction "id:2780,phase:1,pass,setvar:'tx.ready=1'"`}
	second := secLangFile{Name: "rules/200-check.conf", Source: `SecRule TX:ready "@eq 1" "id:2781,phase:1,deny"`}
	for _, files := range [][]secLangFile{{first, second}, {second, first}} {
		input, _ := json.Marshal(secLangFixture{Files: files, Variables: map[string][]string{}, Threshold: 5})
		var output bytes.Buffer
		if err := runSecLangCLI(bytes.NewReader(input), &output, true); err != nil {
			t.Fatal(err)
		}
		var got secResult
		if err := json.Unmarshal(output.Bytes(), &got); err != nil {
			t.Fatal(err)
		}
		if !got.Blocked {
			t.Fatalf("same canonical source digest changed behavior after file reordering: %s", output.String())
		}
	}
}

func TestSecLangCRSBlockAccumulatesAllRuleScoresBeforeThresholdDecision(t *testing.T) {
	source := `SecRule ARGS:q "@contains attack" "id:2790,phase:2,block,setvar:'tx.inbound_anomaly_score_pl1=+3'"
SecRule ARGS:q "@contains attack" "id:2791,phase:2,block,setvar:'tx.inbound_anomaly_score_pl1=+3'"`
	rules, err := parseSecLang("scores.conf", source)
	if err != nil {
		t.Fatal(err)
	}
	for _, threshold := range []int{5, 10} {
		got, err := evaluateSecLang(rules, map[string][]string{"ARGS:q": {"attack"}}, threshold)
		if err != nil || got.Blocked != (threshold == 5) || got.Score != 6 || len(got.Matches) != 2 {
			t.Fatalf("threshold %d: %+v %v", threshold, got, err)
		}
	}
}
func TestSecLangLogDataKeepsHashesAndContextWithoutRawRequestSecrets(t *testing.T) {
	rules, err := parseSecLang("evidence.conf", `SecRule ARGS:password "@contains secret" "id:2792,phase:2,deny,msg:'Suspicious parameter',tag:attack-test,logdata:'value=%{matched_var}'"`)
	if err != nil {
		t.Fatal(err)
	}
	got, err := evaluateSecLang(rules, map[string][]string{"ARGS:password": {"secret-fixture-value"}}, 5)
	if err != nil || !got.Blocked {
		t.Fatalf("%+v %v", got, err)
	}
	raw, _ := json.Marshal(got)
	if strings.Contains(string(raw), "secret-fixture-value") || !strings.Contains(string(raw), "valueSha256") || !strings.Contains(string(raw), "ARGS:password") {
		t.Fatalf("unsafe or untraceable match evidence: %s", raw)
	}
}

func TestSecLangNonDisruptiveActionsRunForEveryMatchedValueAndStage(t *testing.T) {
	rules, err := parseSecLang("per-match.conf", `SecRule ARGS_NAMES "@unconditionalMatch" "id:2820,phase:2,pass,setvar:'tx.counter_%{matched_var}=+1'"
SecRule TX:counter_foo "@ge 2" "id:2821,phase:2,deny"`)
	if err != nil {
		t.Fatal(err)
	}
	got, err := evaluateSecLang(rules, map[string][]string{"ARGS_NAMES": {"foo", "foo", "bar"}}, 5)
	if err != nil || !got.Blocked || got.Variables["counter_foo"] != "2" || got.Variables["counter_bar"] != "1" {
		t.Fatalf("per-variable actions lost: %+v %v", got, err)
	}
	rules, err = parseSecLang("per-stage.conf", `SecRule ARGS "@contains attack" "id:2822,phase:2,block,t:none,t:lowercase,multiMatch,setvar:'tx.inbound_anomaly_score_pl1=+1'"`)
	if err != nil {
		t.Fatal(err)
	}
	got, err = evaluateSecLang(rules, map[string][]string{"ARGS:q": {"attackXYZ"}}, 3)
	if err != nil || got.Blocked || got.Score != 2 {
		t.Fatalf("per-stage actions lost: %+v %v", got, err)
	}
}
func TestSecLangOperatorMacrosReflectEarlierMatchActions(t *testing.T) {
	rules, err := parseSecLang("changing-operand.conf", `SecAction "id:2823,phase:1,pass,setvar:'tx.limit=1'"
SecRule ARGS "@eq %{tx.limit}" "id:2824,phase:2,pass,setvar:'tx.limit=+1'"`)
	if err != nil {
		t.Fatal(err)
	}
	got, err := evaluateSecLang(rules, map[string][]string{"ARGS:q": {"1", "2"}}, 5)
	if err != nil || got.Variables["limit"] != "3" {
		t.Fatalf("stale operator operand: %+v %v", got, err)
	}
	rules, err = parseSecLang("absent-unconditional.conf", `SecRule ARGS:nope "@unconditionalMatch" "id:2825,phase:2,deny"`)
	if err != nil {
		t.Fatal(err)
	}
	got, err = evaluateSecLang(rules, map[string][]string{}, 5)
	if err != nil || got.Blocked {
		t.Fatalf("nonexistent variable invoked operator: %+v %v", got, err)
	}
}
