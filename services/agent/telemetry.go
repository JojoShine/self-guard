package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"regexp"
	"time"
)

var telemetryIdentifier = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,100}$`)

func (a *Agent) collectorTelemetry(findings []map[string]any) ([]Pending, error) {
	events := []map[string]any{}
	for _, finding := range findings {
		source, _ := finding["source"].(string)
		eventType := ""
		switch source {
		case "agent-log":
			eventType = "HOST_LOG"
		case "agent-fim":
			eventType = "FIM_CHANGE"
		default:
			continue
		}
		externalID, _ := finding["externalId"].(string)
		if externalID == "" {
			continue
		}
		data := map[string]string{"category": source}
		var evidence map[string]any
		switch value := finding["evidence"].(type) {
		case string:
			json.Unmarshal([]byte(value), &evidence)
		case map[string]any:
			evidence = value
		case map[string]string:
			if rule := value["ruleId"]; telemetryIdentifier.MatchString(rule) {
				data["ruleId"] = rule
			}
		}
		if rule, ok := evidence["ruleId"].(string); ok && telemetryIdentifier.MatchString(rule) {
			data["ruleId"] = rule
		}
		id := fmt.Sprintf("%x", sha256.Sum256([]byte(a.Identity.AssetID+":"+externalID)))
		events = append(events, map[string]any{"id": id, "type": eventType, "timestamp": time.Now().UTC().Format(time.RFC3339Nano), "data": data})
	}
	if a.Config.LogIncludeMessage {
		if _, err := compileLogRedactions(a.Config); err == nil {
			for _, line := range a.LogContexts {
				events = append(events, map[string]any{"id": line.ID, "type": "HOST_LOG_LINE", "timestamp": line.Timestamp.UTC().Format(time.RFC3339Nano), "data": map[string]string{"category": "agent-log", "message": line.Message}})
			}
		}
	}
	batch := []Pending{}
	for start := 0; start < len(events); start += 100 {
		end := start + 100
		if end > len(events) {
			end = len(events)
		}
		b, err := json.Marshal(map[string]any{"events": events[start:end]})
		if err != nil {
			return nil, err
		}
		batch = append(batch, Pending{"/telemetry/events", b})
	}
	return batch, nil
}
