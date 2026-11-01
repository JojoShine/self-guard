package main

import "testing"

func TestInspectionLimitsCannotCountAsParserOrExpectedProtocolRejection(t *testing.T) {
	for _, row := range []struct{ message, kind string }{
		{"malformed HTTP sample\n", "HTTP_PARSE_REJECTED"},
		{"malformed content type\n", "REQUEST_FIELD_INCOMPLETE"},
		{"PCRE2 compilation or execution budget failure (-47)\n", "INSPECTION_BUDGET"},
		{"malformed UTF-8; Unicode transformation incomplete\n", "TRANSFORMATION_INCOMPLETE"},
		{"unexpected failure", "WORKER_FAILURE"},
	} {
		if got := failureKind(row.message, false); got != row.kind {
			t.Fatalf("%q: got %s want %s", row.message, got, row.kind)
		}
	}
	if got := failureKind("malformed HTTP sample", true); got != "WORKER_DEADLINE" {
		t.Fatal(got)
	}
}
