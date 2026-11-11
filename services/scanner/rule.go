package scanner

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
)

// RuleSample is an explicitly supplied offline response, never a network request.
type RuleSample struct {
	responseRaw    string
	responseProto  string
	responseStatus string
	Status         int         `json:"status"`
	Headers        http.Header `json:"headers"`
	Body           string      `json:"body"`
}
type RuleEvaluation struct {
	Native     *NativeEvidence     `json:"native,omitempty"`
	Groups     []GroupEvidence     `json:"groups,omitempty"`
	Matched    bool                `json:"matched"`
	Conditions []ConditionEvidence `json:"conditions"`
}

func CheckRule(method string, rule HTTPRule, sample RuleSample) (RuleEvaluation, error) {
	if method != "GET" && method != "HEAD" {
		return RuleEvaluation{}, errors.New("only read-only GET or HEAD is supported")
	}
	expressions, err := validateHTTPRule(rule, method)
	if err != nil {
		return RuleEvaluation{}, err
	}
	if sample.Status < 100 || sample.Status > 599 || len(sample.Body) > 1<<20 || method == "HEAD" && sample.Body != "" {
		return RuleEvaluation{}, errors.New("invalid offline response budget")
	}
	headers := make(http.Header)
	size := 0
	for name, values := range sample.Headers {
		if !headerName.MatchString(name) {
			return RuleEvaluation{}, errors.New("invalid sample header")
		}
		for _, value := range values {
			size += len(name) + len(value) + 4
			if size > 16<<10 || strings.ContainsAny(value, "\r\n\x00") {
				return RuleEvaluation{}, errors.New("invalid sample header budget")
			}
			headers.Add(name, value)
		}
	}
	if !requiredHeadersAvailable(rule, headers) {
		return RuleEvaluation{}, errors.New("sample missing required response header")
	}
	view := ""
	if needsResponseView(rule) {
		response := &http.Response{Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1, StatusCode: sample.Status, Status: strconv.Itoa(sample.Status) + " " + http.StatusText(sample.Status), Header: headers, ContentLength: int64(len(sample.Body))}
		view, err = responseMatchView(response, []byte(sample.Body))
		if err != nil {
			return RuleEvaluation{}, err
		}
	}
	if rule.NativeTemplate != nil {
		matched, proof, err := nativeRun(context.Background(), rule, &RuleSample{Status: sample.Status, Headers: headers, Body: sample.Body})
		return RuleEvaluation{Matched: matched, Conditions: []ConditionEvidence{}, Native: proof}, err
	}
	matched, conditions, groups := evaluateHTTPRule(rule, expressions.conditions, sample.Status, headers, []byte(sample.Body), view)
	// Offline reports retain the minimal sample contract; observed values are
	// reserved for actual HTTP response evidence.
	for index := range conditions {
		conditions[index].Observed = ""
	}
	for gi := range groups {
		for ci := range groups[gi].Conditions {
			groups[gi].Conditions[ci].Observed = ""
		}
	}
	return RuleEvaluation{Matched: matched, Conditions: conditions, Groups: groups}, nil
}
