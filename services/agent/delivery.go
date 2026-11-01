package main

import (
	"encoding/json"
	"errors"
	"net/url"
	"path/filepath"
)

func (a *Agent) heartbeat(inventory any, findings []map[string]any) error {
	for _, f := range findings {
		if _, ok := f["evidence"].(string); !ok {
			b, e := json.Marshal(f["evidence"])
			if e != nil {
				return e
			}
			f["evidence"] = string(b)
		}
	}
	batch := []Pending{}
	for start := 0; start < len(findings) || start == 0; start += 100 {
		end := start + 100
		if end > len(findings) {
			end = len(findings)
		}
		b, e := json.Marshal(map[string]any{"inventory": inventory, "findings": findings[start:end]})
		if e != nil {
			return e
		}
		if len(b) > 1<<20 {
			return errors.New("report too large")
		}
		batch = append(batch, Pending{"/agent/heartbeat", b})
	}
	telemetry, err := a.collectorTelemetry(findings)
	if err != nil {
		return err
	}
	batch = append(batch, telemetry...)
	if len(a.Queue)+len(batch) > 128 {
		return errors.New("offline queue full")
	}
	next := append(append([]Pending{}, a.Queue...), batch...)
	if a.Config.MaxQueueBytes > 0 {
		var size int64
		for _, p := range next {
			size += int64(len(p.Body))
		}
		if size > a.Config.MaxQueueBytes {
			return errors.New("offline queue byte budget reached")
		}
	}
	if e := writePrivate(filepath.Join(a.Config.StateDir, "queue.json"), next); e != nil {
		return e
	}
	a.Queue = next
	return nil
}
func (a *Agent) sendResults() error {
	if a.Ack == nil {
		a.Ack = map[string]bool{}
	}
	for id, r := range a.Done {
		if a.Ack[id] {
			continue
		}
		if e := a.request("POST", "/agent/tasks/"+url.PathEscape(id)+"/result", a.Identity.Token, r, nil); e != nil {
			return e
		}
		a.Ack[id] = true
		if e := writePrivate(filepath.Join(a.Config.StateDir, "ack.json"), a.Ack); e != nil {
			delete(a.Ack, id)
			return e
		}
	}
	return nil
}
