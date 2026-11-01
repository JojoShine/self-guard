package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"testing"
)

func TestSecLangRawRequestRetainsEmptyHostAndConsumedTransferEncoding(t *testing.T) {
	for _, sample := range []struct{ raw, rule string }{
		{"GET / HTTP/1.0\r\nHost:\r\n\r\n", `SecRule REQUEST_HEADERS:Host "@rx ^$" "id:2860,phase:1,deny"`},
		{"GET / HTTP/1.1\r\nHost: fixture.test\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n", `SecRule REQUEST_HEADERS:Transfer-Encoding "@streq chunked" "id:2861,phase:1,deny"`},
		{"GET / HTTP/1.0\r\n\r\n", `SecRule &REQUEST_HEADERS:Host "@eq 0" "id:2862,phase:1,deny"`},
	} {
		fixture, _ := json.Marshal(secLangFixture{Files: []secLangFile{{Name: "wire.conf", Source: sample.rule}}, RequestBase64: base64.StdEncoding.EncodeToString([]byte(sample.raw))})
		var out bytes.Buffer
		if err := runSecLangCLI(bytes.NewReader(fixture), &out, true); err != nil {
			t.Fatal(err)
		}
		var result secResult
		if err := json.Unmarshal(out.Bytes(), &result); err != nil || !result.Blocked {
			t.Fatalf("wire header lost: %+v %v", result, err)
		}
	}
}
