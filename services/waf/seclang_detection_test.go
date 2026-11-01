package main

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestSecOwnDetectorsDistinguishGrammarAndBenignWords(t *testing.T) {
	for _, tc := range []struct {
		op, value string
		want      bool
	}{
		{"detectsqli", "1234 OR 1=1", true}, {"detectsqli", "foo') UNION ALL select NULL --", true},
		{"detectsqli", "1; DROP TABLE accounts", true}, {"detectsqli", "sleep(20)", true},
		{"detectsqli", "the workers' union select committee", false}, {"detectsqli", "select an item from the catalog", false},
		{"detectsqli", "sleep well and benchmark results tomorrow", false}, {"detectsqli", "O'Reilly", false},
		{"detectsqli", "1 OR 1", false}, {"detectsqli", "normal x = 10 and y = 20", false},
		{"detectxss", `<svg/onload=alert(1)>`, true}, {"detectxss", `<IMG SRC="java&#x0a;script:alert(1)">`, true},
		{"detectxss", `<x:script xmlns:x="urn:test">x</x:script>`, true},
		{"detectxss", `<a href="https://example.test">ordinary</a>`, false},
		{"detectxss", `<p>one < two and three > two</p>`, false}, {"detectxss", "javascript lessons and onload examples", false},
	} {
		ok, err := matchSecOperator(tc.op, "", tc.value)
		if err != nil || ok != tc.want {
			t.Fatalf("%s %q: %v want %v (%v)", tc.op, tc.value, ok, tc.want, err)
		}
	}
}
func TestSecOwnDetectorsFrozenCRSCoreOperatorSamples(t *testing.T) {
	for _, id := range []int{941100, 942100} {
		t.Run(fmt.Sprint(id), func(t *testing.T) {
			var corpus struct {
				Tests []struct {
					ID     int `json:"test_id"`
					Stages []struct {
						Input struct {
							Method, URI, Data, Version string
							Headers                    map[string]string
						}
						Output struct {
							Log struct {
								Expect []int `json:"expect_ids"`
								Not    []int `json:"no_expect_ids"`
							}
						}
					}
				}
			}
			data, err := os.ReadFile(fmt.Sprintf("testdata/crs-v4.25.1/%d.json", id))
			if err != nil {
				t.Fatal(err)
			}
			if err = json.Unmarshal(data, &corpus); err != nil {
				t.Fatal(err)
			}
			for _, tc := range corpus.Tests {
				t.Run(fmt.Sprint(tc.ID), func(t *testing.T) {
					for _, stage := range tc.Stages {
						r := httptest.NewRequest(stage.Input.Method, "http://localhost"+stage.Input.URI, nil)
						for name, value := range stage.Input.Headers {
							r.Header.Set(name, value)
						}
						if r.Method == "POST" && r.Header.Get("Content-Type") == "" {
							r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
						}
						input, err := secRequestInput(r, []byte(stage.Input.Data))
						if err != nil {
							t.Fatal(err)
						}
						targets := "REQUEST_COOKIES|REQUEST_COOKIES_NAMES|REQUEST_HEADERS:User-Agent|ARGS_NAMES|ARGS|XML:/*|XML://@*"
						operator := "detectXSS"
						transforms := "t:none,t:utf8toUnicode,t:urlDecodeUni,t:htmlEntityDecode,t:jsDecode,t:cssDecode,t:removeNulls"
						if id == 942100 {
							targets += "|REQUEST_HEADERS:Referer"
							operator = "detectSQLi"
							transforms = "t:none,t:utf8toUnicode,t:urlDecodeUni,t:removeNulls,multiMatch,capture"
						}
						rules, err := parseSecLang("official-core-sample.conf", fmt.Sprintf(`SecRule %s "@%s" "id:%d,phase:2,deny,%s"`, targets, operator, id, transforms))
						if err != nil {
							t.Fatal(err)
						}
						result, err := evaluateSecLang(rules, input, 5)
						if err != nil {
							t.Fatal(err)
						}
						want := len(stage.Output.Log.Expect) > 0
						if result.Blocked != want {
							t.Fatalf("official rule %d sample %d blocked=%v expected=%v", id, tc.ID, result.Blocked, want)
						}
					}
				})
			}
		})
	}
}
func TestSecOwnDetectorResourceLimitIsNotClean(t *testing.T) {
	for _, op := range []string{"detectsqli", "detectxss"} {
		if _, err := matchSecOperator(op, "", strings.Repeat("a", (1<<20)+1)); err == nil {
			t.Fatalf("unbounded %s accepted", op)
		}
	}
}
