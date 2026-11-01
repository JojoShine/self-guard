package main

import (
	"sync"
	"time"
)

const (
	accessHandlerStage = iota
	accessHistoryStage
	accessQueueStage
	accessCompletionStage
)

// Fixed histograms contain durations and counts only, never observations or IDs.
var accessLatencyBounds = [...]int64{100, 500, 1000, 2000, 5000, 10000, 20000, 50000, 100000, 500000, 1000000}

type accessStageLatency struct {
	Count       uint64     `json:"count"`
	Errors      uint64     `json:"errors"`
	TotalMicros uint64     `json:"totalMicros"`
	MaxMicros   uint64     `json:"maxMicros"`
	Buckets     [12]uint64 `json:"buckets"`
}
type accessWriteSnapshot struct {
	BoundsMicros       [11]int64          `json:"boundsMicros"`
	HandlerBeforeAudit accessStageLatency `json:"handlerBeforeAudit"`
	History            accessStageLatency `json:"history"`
	Queue              accessStageLatency `json:"queue"`
	AuditCompletion    accessStageLatency `json:"auditCompletion"`
}
type accessWriteDiagnostics struct {
	mu     sync.Mutex
	stages [4]accessStageLatency
}

func (d *accessWriteDiagnostics) observe(stage int, elapsed time.Duration, failed bool) {
	micros := uint64(elapsed.Microseconds())
	d.mu.Lock()
	defer d.mu.Unlock()
	value := &d.stages[stage]
	value.Count++
	value.TotalMicros += micros
	value.MaxMicros = max(value.MaxMicros, micros)
	if failed {
		value.Errors++
	}
	bucket := len(accessLatencyBounds)
	for index, bound := range accessLatencyBounds {
		if micros <= uint64(bound) {
			bucket = index
			break
		}
	}
	value.Buckets[bucket]++
}
func (d *accessWriteDiagnostics) measure(stage int, write func() error) error {
	if d == nil {
		return write()
	}
	started := time.Now()
	err := write()
	d.observe(stage, time.Since(started), err != nil)
	return err
}
func (d *accessWriteDiagnostics) snapshot() accessWriteSnapshot {
	d.mu.Lock()
	defer d.mu.Unlock()
	return accessWriteSnapshot{accessLatencyBounds, d.stages[accessHandlerStage], d.stages[accessHistoryStage], d.stages[accessQueueStage], d.stages[accessCompletionStage]}
}
