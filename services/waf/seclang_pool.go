package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"sort"
	"sync"
	"time"
)

var errSecPoolCapacity = errors.New("rule pool pending capacity reached")

const secInspectionAdmissionLimit = 64

type secPoolPolicy struct {
	initial []byte
	digest  string
}

func prepareSecPoolPolicy(files []secLangFile) (*secPoolPolicy, error) {
	files = append([]secLangFile(nil), files...)
	sort.Slice(files, func(i, j int) bool { return files[i].Name < files[j].Name })
	initial, err := json.Marshal(secLangFixture{Files: files})
	if err != nil || len(initial) > 4<<20 {
		return nil, errors.New("worker policy exceeds budget")
	}
	sum := sha256.Sum256(initial)
	return &secPoolPolicy{initial, hex.EncodeToString(sum[:])}, nil
}

type secPooledProcess struct {
	command  *exec.Cmd
	stdin    io.WriteCloser
	stdout   io.ReadCloser
	done     chan struct{}
	stopOnce sync.Once
	requests int
}

func (w *secPooledProcess) stop() {
	w.stopOnce.Do(func() { w.stdin.Close(); _ = w.command.Process.Kill() })
	<-w.done
	w.stdout.Close()
}
func (w *secPooledProcess) exchange(ctx context.Context, input []byte) (secStreamResponse, error) {
	if err := ctx.Err(); err != nil {
		return secStreamResponse{}, secFailure("WORKER_DEADLINE", err)
	}
	type outcome struct {
		response secStreamResponse
		err      error
	}
	ready := make(chan outcome, 1)
	go func() {
		var response secStreamResponse
		err := writeSecFrame(w.stdin, input)
		if err == nil {
			var raw []byte
			raw, err = readSecFrame(w.stdout, 2<<20)
			if err == nil {
				err = json.Unmarshal(raw, &response)
			}
		}
		ready <- outcome{response, err}
	}()
	select {
	case answer := <-ready:
		if answer.err != nil {
			w.stop()
			kind := "WORKER_PROTOCOL"
			if errors.Is(answer.err, io.EOF) || errors.Is(answer.err, io.ErrUnexpectedEOF) {
				kind = "WORKER_UNAVAILABLE"
			}
			return secStreamResponse{}, secFailure(kind, errors.New("isolated rule process failed or returned an invalid frame"))
		}
		return answer.response, nil
	case <-ctx.Done():
		w.stop()
		<-ready
		return secStreamResponse{}, secFailure("WORKER_DEADLINE", ctx.Err())
	}
}

type secPoolSlot struct {
	worker    *secPooledProcess
	digest    string
	busy      bool
	used      uint64
	busySince time.Time
}
type secLangPool struct {
	binary           string
	mu               sync.Mutex
	slots            []*secPoolSlot
	changed          chan struct{}
	closed           bool
	started          int
	clock            uint64
	life             context.Context
	cancel           context.CancelFunc
	active           sync.WaitGroup
	pending          chan struct{}
	peakPending      int
	capacityRejected uint64
	rejections       []secPoolRejection
}

func newSecLangPool(binary string, size int) *secLangPool {
	if size < 1 || size > 3 {
		panic("rule pool must leave one of four process slots available for management")
	}
	life, cancel := context.WithCancel(context.Background())
	p := &secLangPool{binary: binary, changed: make(chan struct{}), pending: make(chan struct{}, secInspectionAdmissionLimit), life: life, cancel: cancel}
	for i := 0; i < size; i++ {
		p.slots = append(p.slots, &secPoolSlot{})
	}
	return p
}
func (p *secLangPool) notify() { close(p.changed); p.changed = make(chan struct{}) }
func (p *secLangPool) start(ctx context.Context, policy *secPoolPolicy) (*secPooledProcess, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	select {
	case secWorkerSlots <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if err := ctx.Err(); err != nil {
		<-secWorkerSlots
		return nil, err
	}
	command := exec.Command(p.binary, "--serve-seclang")
	command.Env = []string{"PATH=/usr/bin:/bin", "GOMAXPROCS=1", "GOMEMLIMIT=128MiB"}
	stdin, err := command.StdinPipe()
	if err != nil {
		<-secWorkerSlots
		return nil, err
	}
	stdout, childOutput, err := os.Pipe()
	if err != nil {
		stdin.Close()
		<-secWorkerSlots
		return nil, err
	}
	// Own the read descriptor: Cmd.Wait closes a StdoutPipe before a delayed
	// reader can consume the final buffered frame after normal worker exit.
	command.Stdout = childOutput
	diagnostic := &secBoundedBuffer{limit: 8192}
	command.Stderr = diagnostic
	if err = command.Start(); err != nil {
		stdin.Close()
		stdout.Close()
		childOutput.Close()
		<-secWorkerSlots
		return nil, err
	}
	childOutput.Close()
	worker := &secPooledProcess{command: command, stdin: stdin, stdout: stdout, done: make(chan struct{})}
	p.mu.Lock()
	p.started++
	p.mu.Unlock()
	go func() { _ = command.Wait(); <-secWorkerSlots; close(worker.done) }()
	receipt, err := worker.exchange(ctx, policy.initial)
	if err != nil || receipt.Kind != "READY" || receipt.Digest != policy.digest || receipt.Engine != "selfguard-seclang-v1" {
		worker.stop()
		if err != nil {
			return nil, err
		}
		return nil, secFailure("WORKER_PROTOCOL", errors.New("rule process did not confirm the exact immutable policy"))
	}
	return worker, nil
}
func (p *secLangPool) acquire(ctx context.Context, policy *secPoolPolicy) (*secPoolSlot, error) {
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		p.mu.Lock()
		if p.closed {
			p.mu.Unlock()
			return nil, errors.New("rule pool closed")
		}
		var chosen *secPoolSlot
		for _, slot := range p.slots {
			if !slot.busy && slot.worker != nil && slot.digest == policy.digest {
				chosen = slot
				break
			}
		}
		if chosen == nil {
			for _, slot := range p.slots {
				if !slot.busy && (chosen == nil || slot.used < chosen.used) {
					chosen = slot
				}
			}
		}
		if chosen != nil {
			chosen.busy = true
			chosen.busySince = time.Now()
			if chosen.worker != nil && chosen.digest == policy.digest {
				p.mu.Unlock()
				return chosen, nil
			}
			old := chosen.worker
			chosen.worker = nil
			chosen.digest = policy.digest
			p.mu.Unlock()
			if old != nil {
				old.stop()
			}
			worker, err := p.start(ctx, policy)
			p.mu.Lock()
			if err != nil || p.closed {
				chosen.busy = false
				chosen.busySince = time.Time{}
				chosen.digest = ""
				p.notify()
				p.mu.Unlock()
				if worker != nil {
					worker.stop()
				}
				if err != nil {
					return nil, err
				}
				return nil, errors.New("rule pool closed")
			}
			chosen.worker = worker
			p.mu.Unlock()
			return chosen, nil
		}
		changed := p.changed
		p.mu.Unlock()
		select {
		case <-changed:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

// Activation is serialized by the engine configuration lock. Hold acquired
// slots until every slot has acknowledged this exact immutable policy.
func (p *secLangPool) warmPolicy(parent context.Context, policy *secPoolPolicy) error {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return errors.New("rule pool closed")
	}
	ready := 0
	for _, slot := range p.slots {
		if slot.worker != nil && slot.digest == policy.digest {
			ready++
		}
	}
	if ready == len(p.slots) {
		p.mu.Unlock()
		return nil
	}
	p.active.Add(1)
	p.mu.Unlock()
	defer p.active.Done()
	ctx, cancel := context.WithTimeout(parent, 2*time.Second)
	defer cancel()
	detach := context.AfterFunc(p.life, cancel)
	defer detach()
	held := []*secPoolSlot{}
	defer func() {
		for _, slot := range held {
			p.release(slot, true, policy)
		}
	}()
	for range p.slots {
		slot, err := p.acquire(ctx, policy)
		if err != nil {
			return err
		}
		held = append(held, slot)
	}
	return nil
}

func (p *secLangPool) replenish(slot *secPoolSlot, policy *secPoolPolicy) {
	defer p.active.Done()
	ctx, cancel := context.WithTimeout(p.life, 2*time.Second)
	defer cancel()
	worker, err := p.start(ctx, policy)
	p.mu.Lock()
	accepted := err == nil && !p.closed
	if accepted {
		slot.worker = worker
	} else {
		slot.digest = ""
	}
	slot.busy = false
	slot.busySince = time.Time{}
	p.notify()
	p.mu.Unlock()
	if worker != nil && !accepted {
		worker.stop()
	}
}

func (p *secLangPool) release(slot *secPoolSlot, healthy bool, policy *secPoolPolicy) {
	p.mu.Lock()
	worker := slot.worker
	discard := !healthy || p.closed || worker.requests >= secStreamRequestLimit
	replenish := healthy && !p.closed && worker.requests >= secStreamRequestLimit && len(p.slots) > 1
	if discard {
		slot.worker = nil
		slot.digest = ""
	}
	slot.busy = replenish
	slot.busySince = time.Time{}
	if replenish {
		slot.busySince = time.Now()
		slot.digest = policy.digest
		p.active.Add(1)
	}
	p.clock++
	slot.used = p.clock
	p.notify()
	p.mu.Unlock()
	if discard {
		worker.stop()
	}
	if replenish {
		go p.replenish(slot, policy)
	}
}
func (p *secLangPool) evaluate(ctx context.Context, files []secLangFile, fixture secLangFixture) (secResult, error) {
	policy, err := prepareSecPoolPolicy(files)
	if err != nil {
		return secResult{}, err
	}
	return p.evaluatePolicy(ctx, policy, fixture)
}
func (p *secLangPool) evaluatePolicy(parent context.Context, policy *secPoolPolicy, fixture secLangFixture) (secResult, error) {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return secResult{}, errors.New("rule pool closed")
	}
	select {
	case p.pending <- struct{}{}:
	default:
		p.capacityRejected++
		p.peakPending = max(p.peakPending, len(p.pending))
		if len(p.rejections) == 64 {
			copy(p.rejections, p.rejections[1:])
			p.rejections = p.rejections[:63]
		}
		p.rejections = append(p.rejections, secPoolRejection{At: time.Now(), Slots: p.slotDiagnostics()})
		p.mu.Unlock()
		return secResult{}, errSecPoolCapacity
	}
	p.peakPending = max(p.peakPending, len(p.pending))
	p.active.Add(1)
	p.mu.Unlock()
	defer func() { <-p.pending; p.active.Done() }()
	ctx, cancel := context.WithTimeout(parent, 2*time.Second)
	defer cancel()
	detach := context.AfterFunc(p.life, cancel)
	defer detach()
	if len(fixture.Files) > 0 {
		return secResult{}, secFailure("REQUEST_INVALID", errors.New("request cannot replace immutable policy"))
	}
	request := struct {
		Variables     *map[string][]string `json:"variables,omitempty"`
		RequestBase64 string               `json:"requestBase64,omitempty"`
		Threshold     int                  `json:"threshold,omitempty"`
		Request       *secLiveRequest      `json:"request,omitempty"`
	}{RequestBase64: fixture.RequestBase64, Threshold: fixture.Threshold, Request: fixture.Request}
	if fixture.Variables != nil {
		request.Variables = &fixture.Variables
	}
	raw, err := json.Marshal(request)
	if err != nil || len(raw) > 4<<20 {
		return secResult{}, secFailure("REQUEST_INVALID", errors.New("worker request exceeds budget"))
	}
	slot, err := p.acquire(ctx, policy)
	if err != nil {
		var failure *secInspectionFailure
		if errors.As(err, &failure) {
			return secResult{}, err
		}
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			return secResult{}, secFailure("QUEUE_TIMEOUT", err)
		}
		return secResult{}, secFailure("WORKER_UNAVAILABLE", err)
	}
	healthy := false
	defer func() { p.release(slot, healthy, policy) }()
	response, err := slot.worker.exchange(ctx, raw)
	if err != nil {
		return secResult{}, err
	}
	slot.worker.requests++
	if response.Sequence != slot.worker.requests || response.Kind != "RESULT" && response.Kind != "ERROR" {
		return secResult{}, secFailure("WORKER_PROTOCOL", errors.New("worker response correlation failed"))
	}
	if response.Kind == "ERROR" {
		if response.Status != "INCOMPLETE" || response.Message == "" {
			return secResult{}, secFailure("WORKER_PROTOCOL", errors.New("invalid worker error response"))
		}
		healthy = true
		return secResult{}, secFailure("REQUEST_INCOMPLETE", errors.New(response.Message))
	}
	if response.Result == nil {
		return secResult{}, secFailure("WORKER_PROTOCOL", errors.New("worker result missing"))
	}
	if response.Status != "COMPLETED" && response.Status != "INCOMPLETE" {
		return secResult{}, secFailure("WORKER_PROTOCOL", errors.New("invalid worker result status"))
	}
	healthy = true
	if response.Status != "COMPLETED" || len(response.Result.Incomplete) > 0 {
		return *response.Result, secFailure("REQUEST_INCOMPLETE", errors.New("request inspection incomplete"))
	}
	return *response.Result, nil
}
func (p *secLangPool) stats() int { p.mu.Lock(); defer p.mu.Unlock(); return p.started }
func (p *secLangPool) discardIdle() {
	p.mu.Lock()
	workers := []*secPooledProcess{}
	for _, slot := range p.slots {
		if !slot.busy && slot.worker != nil {
			workers = append(workers, slot.worker)
			slot.worker = nil
			slot.digest = ""
		}
	}
	p.notify()
	p.mu.Unlock()
	for _, worker := range workers {
		worker.stop()
	}
}
func (p *secLangPool) close() {
	p.mu.Lock()
	p.closed = true
	p.cancel()
	workers := []*secPooledProcess{}
	for _, slot := range p.slots {
		if slot.worker != nil {
			workers = append(workers, slot.worker)
		}
	}
	p.notify()
	p.mu.Unlock()
	for _, worker := range workers {
		worker.stop()
	}
	p.active.Wait()
}
