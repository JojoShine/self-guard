package main

import (
	"context"
	"errors"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestRulePoolAcceptsBoundedBurstDuringTransientBusyWorkers(t *testing.T) {
	pool := newSecLangPool(poolTestBinary(t), 3)
	defer pool.close()
	policy, err := prepareSecPoolPolicy([]secLangFile{{Name: "a.conf", Source: `SecRule ARGS:q "@contains attack" "id:1001,phase:2,deny"`}})
	if err != nil {
		t.Fatal(err)
	}
	if err = pool.warmPolicy(context.Background(), policy); err != nil {
		t.Fatal(err)
	}
	var held []*secPoolSlot
	for i := 0; i < 3; i++ {
		slot, err := pool.acquire(context.Background(), policy)
		if err != nil {
			t.Fatal(err)
		}
		held = append(held, slot)
	}
	released := false
	release := func() {
		if !released {
			released = true
			for _, slot := range held {
				pool.release(slot, true, policy)
			}
		}
	}
	defer release()
	const requests = 32
	outcomes := make(chan error, requests)
	for i := 0; i < requests; i++ {
		go func() {
			result, err := pool.evaluatePolicy(context.Background(), policy, secLangFixture{Variables: map[string][]string{"ARGS:q": {"attack"}}})
			if err == nil && !result.Blocked {
				err = errors.New("actual rule did not inspect the admitted request")
			}
			outcomes <- err
		}()
	}
	deadline := time.Now().Add(time.Second)
	for {
		value := pool.diagnostics()
		if uint64(value.Pending)+value.CapacityRejected >= requests {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("owned requests did not reach admission")
		}
		time.Sleep(time.Millisecond)
	}
	release()
	for i := 0; i < requests; i++ {
		if err := <-outcomes; err != nil {
			t.Errorf("bounded legitimate burst was dropped instead of waiting within the existing deadline: %v", err)
		}
	}
}

type admissionBlockedBody struct {
	entered chan<- struct{}
	release <-chan struct{}
	read    *atomic.Bool
}

func (b admissionBlockedBody) Read([]byte) (int, error) {
	if b.read != nil {
		b.read.Store(true)
	}
	if b.entered != nil {
		b.entered <- struct{}{}
	}
	if b.release != nil {
		<-b.release
	}
	return 0, errors.New("owned body stops before rule execution")
}
func (admissionBlockedBody) Close() error { return nil }

func TestHTTPAdmissionBoundsBodyReadersBeforeAllocatingInspectionPayloads(t *testing.T) {
	for _, tc := range []struct {
		name    string
		body    int64
		readers int
	}{{"one-MiB", 1 << 20, 64}, {"eight-MiB", 8 << 20, 8}} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEngine()
			e.sites.Store(map[string]runtimeSite{"admission.fixture.test": {Site: Site{ID: "owned-body-admission", Hostname: "admission.fixture.test", Enabled: true, Mode: "BLOCK", Config: Policy{MaxBodyBytes: tc.body, RatePerMinute: 100000}}, rulePolicy: &secRuntimePolicy{}}})
			entered, release := make(chan struct{}, tc.readers), make(chan struct{})
			var work sync.WaitGroup
			var releaseOnce sync.Once
			releaseAll := func() { releaseOnce.Do(func() { close(release) }); work.Wait() }
			defer releaseAll()
			for i := 0; i < tc.readers; i++ {
				work.Add(1)
				go func() {
					defer work.Done()
					request := httptest.NewRequest("POST", "http://admission.fixture.test/", nil)
					request.Body = admissionBlockedBody{entered: entered, release: release}
					e.ServeHTTP(httptest.NewRecorder(), request)
				}()
			}
			for i := 0; i < tc.readers; i++ {
				select {
				case <-entered:
				case <-time.After(2 * time.Second):
					t.Fatal("body reader fixture did not reach its bounded admission slot")
				}
			}
			var read atomic.Bool
			request := httptest.NewRequest("POST", "http://admission.fixture.test/", nil)
			request.Body = admissionBlockedBody{read: &read}
			response := httptest.NewRecorder()
			e.ServeHTTP(response, request)
			if response.Code != 503 || read.Load() {
				t.Fatalf("overflow request allocated/read a body: status=%d read=%v", response.Code, read.Load())
			}
			select {
			case event := <-e.events:
				if event.RuleID != "INSPECTION_INCOMPLETE" || event.Inspection == nil || event.Inspection.Complete || event.Inspection.FailureKind != "QUEUE_CAPACITY" {
					t.Fatalf("overflow lacks actual incomplete-check evidence: %+v", event)
				}
			default:
				t.Fatal("overflow was silently dropped")
			}
			releaseAll()
			read.Store(false)
			retry := httptest.NewRequest("POST", "http://admission.fixture.test/", nil)
			retry.Body = admissionBlockedBody{read: &read}
			retried := httptest.NewRecorder()
			e.ServeHTTP(retried, retry)
			if retried.Code != 400 || !read.Load() {
				t.Fatal("completed requests leaked body admission budget")
			}
		})
	}
}
