package main

import (
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"time"
)

type ruleFixture struct {
	Mode     string   `json:"mode"`
	Content  string   `json:"content"`
	State    string   `json:"state"`
	Readable *bool    `json:"readable"`
	Lines    []string `json:"lines"`
	Source   string   `json:"source"`
}

// This entry point consumes observations, never paths to files or commands.
func runRuleTest(input io.Reader, output io.Writer) error {
	var request struct {
		Rule    PolicyRule  `json:"rule"`
		Asset   PolicyAsset `json:"asset"`
		Fixture ruleFixture `json:"fixture"`
	}
	decoder := json.NewDecoder(io.LimitReader(input, (1<<20)+1))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&request) != nil {
		return fmt.Errorf("invalid rule fixture")
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF {
		return fmt.Errorf("invalid fixture suffix")
	}
	r := request.Rule
	now := time.Now()
	result := map[string]any{"status": "COMPLETED", "matched": false, "evidence": map[string]any{}}
	if !ruleApplies(r.Config, request.Asset) {
		result["status"] = "NOT_APPLICABLE"
		return json.NewEncoder(output).Encode(result)
	}
	if r.Kind == "BASELINE" && baselineExempt(r.Config, request.Asset, now) {
		result["status"] = "EXEMPT"
		return json.NewEncoder(output).Encode(result)
	}
	switch r.Kind {
	case "BASELINE":
		c := Check{Type: r.Config.Type, Path: r.Config.Path, Mode: r.Config.Mode, Key: r.Config.Key, Value: r.Config.Value, Service: r.Config.Service, State: r.Config.State}
		kind := c.Type
		if kind == "" {
			kind = "FILE_PERMISSION"
		}
		actual, expected, status := "", c.Mode, "checked"
		if request.Fixture.Readable != nil && !*request.Fixture.Readable {
			status = "unreadable"
		}
		switch kind {
		case "FILE_PERMISSION":
			if !regexp.MustCompile(`^0[0-7]{3}$`).MatchString(request.Fixture.Mode) && status == "checked" {
				return fmt.Errorf("fixture requires an octal file mode")
			}
			actual = request.Fixture.Mode
		case "DATABASE_SECURITY":
			if status == "checked" {
				actual, expected, status = databaseBaseline(c, request.Fixture.Content, request.Fixture.Mode)
			}
		case "CONFIG_VALUE":
			expected = c.Value
			if len(request.Fixture.Content) > 64<<10 || !configKey.MatchString(c.Key) {
				status = "unreadable"
			} else {
				var count int
				actual, count = observedConfigValue(request.Fixture.Content, c.Key)
				if count != 1 {
					status = "missing or duplicate key"
				}
			}
		case "SERVICE_STATE":
			if !validService(c.Service) {
				return fmt.Errorf("invalid service rule")
			}
			actual = request.Fixture.State
			expected = c.State
			if actual != "active" && actual != "inactive" && actual != "failed" {
				status = "unreadable"
			}
		default:
			return fmt.Errorf("unsupported baseline fixture")
		}
		if finding := baselineFinding(c, kind, actual, expected, status); finding != nil {
			result["matched"] = true
			result["evidence"] = finding["evidence"]
		}
		if status != "checked" {
			result["status"] = "UNKNOWN"
		}
	case "LOG":
		if len(request.Fixture.Lines) > 1000 {
			return fmt.Errorf("fixture line count exceeds limit")
		}
		if databaseLogRule(r.Config) {
			_, findings := databaseWindows(nil, r, request.Fixture.Source, request.Fixture.Lines, now)
			result["evidence"] = findings
			for _, f := range findings {
				if f["severity"] == "INFO" {
					result["status"] = "UNKNOWN"
				} else {
					result["matched"] = true
				}
			}
		} else {
			_, matched, count := advanceRuleWindow(logWindow{}, r, request.Fixture.Source, request.Fixture.Lines, now)
			result["matched"] = matched
			result["evidence"] = map[string]any{"ruleId": r.ID, "count": count, "singleBatch": true}
		}
	default:
		return fmt.Errorf("offline fixtures support baseline and log rules")
	}
	return json.NewEncoder(output).Encode(result)
}
