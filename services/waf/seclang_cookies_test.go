package main

import (
	"net/http/httptest"
	"reflect"
	"testing"
)

// The frozen CRS profile uses Netscape/v0 cookie fields. Quotes remain bytes,
// and semicolons remain separators; this is not an RFC2109 quoted-string parser.
// https://github.com/owasp-modsecurity/ModSecurity/blob/v3/master/src/transaction.cc
func TestSecRequestV0CookiesPreserveOriginalValuesDuplicatesAndEmptyNames(t *testing.T) {
	for _, sample := range []struct {
		line string
		want map[string][]string
	}{
		{`q="attack"; q=second; flag`, map[string][]string{"REQUEST_COOKIES:q": {`"attack"`, "second"}, "REQUEST_COOKIES:flag": {""}}},
		{`=payload; normal=value`, map[string][]string{"REQUEST_COOKIES:": {"payload"}, "REQUEST_COOKIES:normal": {"value"}}},
		{`session="unfinished`, map[string][]string{"REQUEST_COOKIES:session": {`"unfinished`}}},
		{`>(cmd)=attack; ＜script＞alert(1)＜/script＞=value`, map[string][]string{"REQUEST_COOKIES:>(cmd)": {"attack"}, "REQUEST_COOKIES:＜script＞alert(1)＜/script＞": {"value"}}},
		{`＜script ＞alert(1)＜/script＞=value`, map[string][]string{"REQUEST_COOKIES:＜script ＞alert(1)＜/script＞": {"value"}, "REQUEST_COOKIES_NAMES": {"＜script ＞alert(1)＜/script＞"}}},
		{`<?php phpinfo(); ?>=value`, map[string][]string{"REQUEST_COOKIES:<?php phpinfo()": {""}, "REQUEST_COOKIES:?>": {"value"}, "REQUEST_COOKIES_NAMES": {"<?php phpinfo()", "?>"}}},
		{`session=<?php phpinfo(); ?>`, map[string][]string{"REQUEST_COOKIES:session": {"<?php phpinfo()"}, "REQUEST_COOKIES:?>": {""}}},
		{`$Version=1; session="deadbeef; PHPSESSID=secret; dummy=qaz"`, map[string][]string{"REQUEST_COOKIES:$Version": {"1"}, "REQUEST_COOKIES:session": {`"deadbeef`}, "REQUEST_COOKIES:PHPSESSID": {"secret"}, "REQUEST_COOKIES:dummy": {`qaz"`}}},
	} {
		request := httptest.NewRequest("GET", "http://fixture.test/", nil)
		request.Header.Set("Cookie", sample.line)
		input, err := secRequestInput(request, nil)
		if err != nil {
			t.Fatalf("original v0 cookie bytes cannot reach rules: %v", err)
		}
		if !reflect.DeepEqual(input["REQUEST_HEADERS:Cookie"], []string{sample.line}) {
			t.Fatal("raw cookie header changed")
		}
		for name, want := range sample.want {
			if !reflect.DeepEqual(input[name], want) {
				t.Fatalf("%s: %q want %q", name, input[name], want)
			}
		}
	}
}

func TestSecRequestAmbiguousCookieNamesAndControlBytesFailClosed(t *testing.T) {
	// Do not imitate parsers that silently discard or rename boundary controls.
	// https://github.com/corazawaf/coraza/security/advisories/GHSA-g4qm-m288-5cp9
	for _, line := range []string{"a\v=payload", "a =payload", "a=\tpayload", "a=payload\x7f", "a\x01b=payload", "na\u00a0me=payload"} {
		request := httptest.NewRequest("GET", "http://fixture.test/", nil)
		request.Header.Set("Cookie", line)
		if _, err := secRequestInput(request, nil); err == nil {
			t.Fatalf("ambiguous cookie silently accepted: %q", line)
		}
	}
}

func TestSecRequestV0CookieAttackBytesRemainAvailableToRules(t *testing.T) {
	request := httptest.NewRequest("GET", "http://fixture.test/", nil)
	request.Header.Set("Cookie", `=payload-attack; session="payload-attack`)
	input, err := secRequestInput(request, nil)
	if err != nil {
		t.Fatal(err)
	}
	rules, err := parseSecLang("cookie.conf", `SecRule REQUEST_COOKIES "@contains payload-attack" "id:2875,phase:2,deny"`)
	if err != nil {
		t.Fatal(err)
	}
	result, err := evaluateSecLang(rules, input, 5)
	if err != nil || !result.Blocked || !contains(result.Matches, "2875") {
		t.Fatalf("cookie attack bytes disappeared: %+v %v", result, err)
	}
}
