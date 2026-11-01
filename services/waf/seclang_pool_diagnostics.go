package main

import (
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"time"
)

type secPoolSlotDiagnostic struct {
	Busy        bool  `json:"busy"`
	WorkerReady bool  `json:"workerReady"`
	BusyMillis  int64 `json:"busyMillis"`
}
type secPoolRejection struct {
	At    time.Time               `json:"at"`
	Slots []secPoolSlotDiagnostic `json:"slots"`
}
type secPoolDiagnostics struct {
	Capacity         int                     `json:"capacity"`
	Pending          int                     `json:"pending"`
	PeakPending      int                     `json:"peakPending"`
	Started          int                     `json:"started"`
	CapacityRejected uint64                  `json:"capacityRejected"`
	Slots            []secPoolSlotDiagnostic `json:"slots"`
	Rejections       []secPoolRejection      `json:"rejections"`
}

// Caller holds mu. No request data or worker-owned transaction state is read.
func (p *secLangPool) slotDiagnostics() []secPoolSlotDiagnostic {
	slots := make([]secPoolSlotDiagnostic, len(p.slots))
	for i, slot := range p.slots {
		var elapsed int64
		if !slot.busySince.IsZero() {
			elapsed = time.Since(slot.busySince).Milliseconds()
		}
		slots[i] = secPoolSlotDiagnostic{slot.busy, slot.worker != nil, elapsed}
	}
	return slots
}
func (p *secLangPool) diagnostics() secPoolDiagnostics {
	p.mu.Lock()
	defer p.mu.Unlock()
	history := make([]secPoolRejection, len(p.rejections))
	for i, record := range p.rejections {
		history[i] = secPoolRejection{record.At, append([]secPoolSlotDiagnostic(nil), record.Slots...)}
	}
	return secPoolDiagnostics{cap(p.pending), len(p.pending), p.peakPending, p.started, p.capacityRejected, p.slotDiagnostics(), history}
}
func (e *engine) rulePoolHandler(token string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if token == "" || subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+token)) != 1 {
			http.Error(w, "component identity required", http.StatusUnauthorized)
			return
		}
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			http.Error(w, "GET required", http.StatusMethodNotAllowed)
			return
		}
		if e.rulePool == nil {
			http.Error(w, "rule pool unavailable", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		var writes *accessWriteSnapshot
		if e.accessWriteTimings != nil {
			snapshot := e.accessWriteTimings.snapshot()
			writes = &snapshot
		}
		json.NewEncoder(w).Encode(struct {
			secPoolDiagnostics
			AccessWrites *accessWriteSnapshot `json:"accessWrites,omitempty"`
		}{e.rulePool.diagnostics(), writes})
	})
}
