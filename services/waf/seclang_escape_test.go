package main

import "testing"

func TestSecEscapeTransformsDecodeBytesWithoutLosingMalformedSuffixes(t *testing.T) {
	for _, tc := range []struct{ transform, input, want string }{
		{"jsDecode", `\uFF53\u0065\x6c\145ct`, "select"},
		{"jsDecode", `\u263a`, ":"},
		{"jsDecode", `\400\377`, " 0\xff"},
		{"jsDecode", `\X41\q\xZ1\`, `X41qxZ1\`},
		{"jsDecode", `a\n\t\0b`, "a\n\t\x00b"},
		{"cssDecode", `\73 elect`, "select"},
		{"cssDecode", `\000073elect`, "select"},
		{"cssDecode", `ja\vascript`, "javascript"},
		{"cssDecode", `\ff53\000065lect`, "select"},
		{"cssDecode", "a\\\nb\\", "ab"},
		{"cssDecode", `\1234567`, "V7"},
		{"escapeSeqDecode", `\x73\X65\154ect`, "select"},
		{"escapeSeqDecode", `\400\777`, "\x00\xff"},
		{"escapeSeqDecode", `\u0041\q\xZ1\`, `u0041qxZ1\`},
	} {
		got, err := transformSecValue(tc.input, []string{tc.transform})
		if err != nil || got != tc.want {
			t.Fatalf("%s %q: %q want %q (%v)", tc.transform, tc.input, got, tc.want, err)
		}
	}
}
func TestSecEscapeTransformsDetectEncodedAttackAndPreserveBenignInput(t *testing.T) {
	for _, transform := range []string{"jsDecode", "cssDecode", "escapeSeqDecode"} {
		rules, err := parseSecLang("escape.conf", `SecRule ARGS "@contains select" "id:2740,phase:2,deny,t:none,t:`+transform+`"`)
		if err != nil {
			t.Fatal(err)
		}
		encoded := `\163elect`
		if transform == "cssDecode" {
			encoded = `\73 elect`
		}
		for _, tc := range []struct {
			value   string
			blocked bool
		}{{encoded, true}, {"ordinary catalog", false}} {
			got, err := evaluateSecLang(rules, map[string][]string{"ARGS:q": {tc.value}}, 5)
			if err != nil || got.Blocked != tc.blocked {
				t.Fatalf("%s: %+v %v", transform, got, err)
			}
		}
	}
}
