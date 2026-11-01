package main

import "testing"

func TestSecUnicodeAndBase64TransformsHaveExplicitByteBoundaries(t *testing.T) {
	for _, tc := range []struct{ transform, input, want string }{
		{"utf8toUnicode", "ASCII", "ASCII"}, {"utf8toUnicode", "\xffé\x80", "\xff%u00e9\x80"}, {"utf8toUnicode", "é全😀", "%u00e9%u5168%u1f600"},
		{"base64Decode", "c2VsZWN0", "select"}, {"base64Decode", "YQ==", "a"},
		{"base64Decode", "YQ==  \r\n", "a"}, {"base64Decode", "Y\nQ==", "a"},
		{"base64Decode", "Y Q==", "Y Q=="}, {"base64Decode", "YQ", "YQ"},
		{"base64Decode", "%bad", "%bad"}, {"base64Decode", "AA==", "\x00"},
	} {
		got, err := transformSecValue(tc.input, []string{tc.transform})
		if err != nil || got != tc.want {
			t.Fatalf("%s %q: %q want %q (%v)", tc.transform, tc.input, got, tc.want, err)
		}
	}
	for _, value := range []string{string([]byte{0xc0, 0xaf}), string([]byte{0xff}), string([]byte{0xed, 0xa0, 0x80})} {
		if got, err := transformSecValue(value, []string{"utf8toUnicode"}); err != nil || got != value {
			t.Fatalf("malformed UTF-8 bytes must remain available to validation: %x (%v)", got, err)
		}
	}
	got, err := transformSecValue("ＳＥＬＥＣＴ", []string{"utf8toUnicode", "urlDecodeUni", "lowercase"})
	if err != nil || got != "select" {
		t.Fatalf("fullwidth evasions: %q %v", got, err)
	}
}

func TestSecMalformedUnicodeDoesNotPreventFollowingValidation(t *testing.T) {
	rules, err := parseSecLang("unicode-validation.conf", `SecRule ARGS:q "@contains harmless" "id:11001,phase:1,t:none,t:utf8toUnicode"
SecRule ARGS:q "@validateUtf8Encoding" "id:920250,phase:2,t:none,deny"`)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{string([]byte{0xc0, 0xaf}), string([]byte{0xc0}), string([]byte{0xf5, 0x80, 0xbf, 0xbf}), string([]byte{0xe2, 0xa3})} {
		result, err := evaluateSecLang(rules, map[string][]string{"ARGS:q": {value}}, 5)
		if err != nil || !result.Blocked {
			t.Fatalf("invalid bytes did not reach explicit validation: %x %+v %v", value, result, err)
		}
	}
	result, err := evaluateSecLang(rules, map[string][]string{"ARGS:q": {"é正常"}}, 5)
	if err != nil || result.Blocked {
		t.Fatalf("valid Unicode rejected: %+v %v", result, err)
	}
}
