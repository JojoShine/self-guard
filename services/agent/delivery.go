package main

import (
	"encoding/json"
	"errors"
	"fmt"
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

	databaseBatch := []Pending{}
	unique := []map[string]any{}
	seen := map[string]bool{}
	for _, pending := range a.DatabaseQueue {
		var body struct {
			Events []map[string]any `json:"events"`
		}
		if json.Unmarshal(pending.Body, &body) != nil {
			return errors.New("invalid durable database queue")
		}
		for _, row := range body.Events {
			seen[fmt.Sprint(row["instanceId"], ":", row["eventId"])] = true
		}
	}

	for _, row := range a.DatabaseEvents {
		key := fmt.Sprint(row["instanceId"], ":", row["eventId"])
		if !seen[key] {
			seen[key] = true
			unique = append(unique, row)
		}
	}
	for start := 0; start < len(unique); {
		end := start + 100
		if end > len(unique) {
			end = len(unique)
		}
  body,err:=json.Marshal(map[string]any{"events":unique[start:end]});if err!=nil{return err}
  for len(body)>1<<20&&end>start+1{end=start+(end-start)/2;body,err=json.Marshal(map[string]any{"events":unique[start:end]});if err!=nil{return err}}
  if len(body)>1<<20{return errors.New("database audit record exceeds delivery budget")}
  databaseBatch=append(databaseBatch,Pending{"/agent/database-audit",body});start=end
	}

	databaseNext := append(append([]Pending{}, a.DatabaseQueue...), databaseBatch...)
	if len(databaseNext) > 64 || pendingBytes(databaseNext) > a.databaseQueueLimit() {
		return errors.New("database audit queue full; collector cursor retained")
	}
	if len(databaseBatch) > 0 {
		if err := writePrivate(filepath.Join(a.Config.StateDir, "database-queue.json"), databaseNext); err != nil {
			return err
		}
		a.DatabaseQueue = databaseNext
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
		size := pendingBytes(a.DatabaseQueue)
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

func pendingBytes(queue []Pending) int64 {
	var total int64
	for _, p := range queue {
		total += int64(len(p.Body))
	}
	return total
}
func (a *Agent) databaseQueueLimit() int64 {
	if a.Config.MaxQueueBytes > 0 {
		return a.Config.MaxQueueBytes / 2
	}
	return 8 << 20
}
func (a *Agent) databaseBackpressure() bool {
	return len(a.DatabaseQueue) >= 48 || pendingBytes(a.DatabaseQueue) > a.databaseQueueLimit()/2 || len(a.DatabaseEvents) >= 100
}
func (a *Agent) flushDatabaseReports() {
	if err:=a.expireDatabaseSQL();err!=nil{a.DatabaseDeliveryError="审计队列到期清理失败，保留游标并暂停投递";return}
	for sent := 0; len(a.DatabaseQueue) > 0 && sent < 1; sent++ {
		pending := a.DatabaseQueue[0]
		if err := a.request("POST", pending.Path, a.Identity.Token, pending.Body, nil); err != nil {
			a.DatabaseDeliveryError = "投递失败，未确认审计仍在独立队列"
			return
		}
		next := a.DatabaseQueue[1:]
		if err := writePrivate(filepath.Join(a.Config.StateDir, "database-queue.json"), next); err != nil {
			a.DatabaseDeliveryError = "审计确认状态保存失败，将重试"
			return
		}
		a.DatabaseQueue = next
	}
	a.DatabaseDeliveryError = ""
}
