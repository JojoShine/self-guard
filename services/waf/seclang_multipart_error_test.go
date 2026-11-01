package main

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMultipartInvalidHeaderPreservesSpecificSafeParserEvidence(t *testing.T) {
	for _, header := range []string{"\x0eContent-Disposition", "Content-Disposition\x0e", "Content\x7f-Disposition"} {
		body := "--boundary\r\n" + header + ": form-data; name=\"unique-sensitive-marker\"\r\nContent-Disposition: form-data; name=\"post\"\r\n\r\nvalue\r\n--boundary--\r\n"
		request := httptest.NewRequest("POST", "https://fixture.test/post", strings.NewReader(body))
		request.Header.Set("Content-Type", "multipart/form-data; boundary=boundary")
		state := secRequestState{request: request, body: []byte(body)}
		input, err := state.load("MULTIPART", false)
		if err != nil {
			t.Fatal(err)
		}
		if input["REQBODY_ERROR"][0] != "1" || !strings.Contains(input["REQBODY_ERROR_MSG"][0], "Invalid part header (contains invalid character)") {
			t.Fatalf("specific parser evidence lost: %+v", input["REQBODY_ERROR_MSG"])
		}
		if strings.Contains(input["REQBODY_ERROR_MSG"][0], "unique-sensitive-marker") {
			t.Fatal("raw part header exposed in parser message")
		}
	}
}
