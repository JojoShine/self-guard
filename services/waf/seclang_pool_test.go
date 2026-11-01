package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func poolTestBinary(t *testing.T) string {
	t.Helper()
	binary := filepath.Join(t.TempDir(), "waf")
	if output, err := exec.Command("go", "build", "-o", binary, ".").CombinedOutput(); err != nil {
		t.Fatalf("%s %v", output, err)
	}
	return binary
}
func TestSecLangPoolReusesRealIsolatedProcessAndRecyclesWithoutStateLeaks(t *testing.T) {
	pool := newSecLangPool(poolTestBinary(t), 1)
	defer pool.close()
	files := []secLangFile{{Name: "a.conf", Source: `SecRule ARGS:q "@contains attack" "id:1001,phase:2,deny,setvar:'tx.hit=1'"`}}
	for i := 0; i < secStreamRequestLimit+2; i++ {
		value := "safe"
		if i%2 == 0 {
			value = "attack"
		}
		result, err := pool.evaluate(context.Background(), files, secLangFixture{Variables: map[string][]string{"ARGS:q": {value}}})
		if err != nil || result.Blocked != (i%2 == 0) {
			t.Fatalf("request %d: %+v %v", i, result, err)
		}
	}
	if pool.stats() != 2 {
		t.Fatal("worker was spawned per request or not recycled")
	}
	if _, err := pool.evaluate(context.Background(), files, secLangFixture{RequestBase64: "AA=="}); err == nil {
		t.Fatal("malformed request became a clean result")
	}
	result, err := pool.evaluate(context.Background(), files, secLangFixture{Variables: map[string][]string{"ARGS:q": {"safe"}}})
	if err != nil || result.Blocked {
		t.Fatalf("failed transaction leaked: %+v %v", result, err)
	}
	if pool.stats() != 2 {
		t.Fatal("ordinary malformed input unnecessarily discarded healthy worker")
	}
	if result, err := pool.evaluate(context.Background(), files, secLangFixture{Variables: map[string][]string{}}); err != nil || result.Blocked {
		t.Fatalf("explicit empty variable fixture lost its presence: %+v %v", result, err)
	}

}
func TestSecLangPoolBoundsConcurrentWorkAndStopsOnDeadline(t *testing.T) {
	pool := newSecLangPool(poolTestBinary(t), 2)
	files := []secLangFile{{Name: "a.conf", Source: `SecRule ARGS:q "@contains attack" "id:1001,phase:2,deny"`}}
	var workers sync.WaitGroup
	for i := 0; i < 10; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			if result, err := pool.evaluate(context.Background(), files, secLangFixture{Variables: map[string][]string{"ARGS:q": {"attack"}}}); err != nil || !result.Blocked {
				t.Errorf("parallel pool: %+v %v", result, err)
			}
		}()
	}
	workers.Wait()
	if pool.stats() > 2 {
		t.Fatal("concurrency capacity exceeded")
	}
	pool.close()
	if _, err := pool.evaluate(context.Background(), files, secLangFixture{}); err == nil {
		t.Fatal("closed pool accepted work")
	}
	sleeper := filepath.Join(t.TempDir(), "slow-worker")
	if err := os.WriteFile(sleeper, []byte("#!/bin/sh\nexec sleep 30\n"), 0700); err != nil {
		t.Fatal(err)
	}
	slow := newSecLangPool(sleeper, 1)
	defer slow.close()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := slow.evaluate(ctx, files, secLangFixture{}); err == nil || time.Since(start) > time.Second {
		t.Fatal("worker deadline did not stop process")
	}
}
func TestSecLangPoolRejectsExcessPendingWorkInsteadOfGrowingWithoutBound(t *testing.T) {
	sleeper := filepath.Join(t.TempDir(), "slow-worker")
	if err := os.WriteFile(sleeper, []byte("#!/bin/sh\nexec sleep 30\n"), 0700); err != nil {
		t.Fatal(err)
	}
	pool := newSecLangPool(sleeper, 1)
	defer pool.close()
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	var workers sync.WaitGroup
	outcomes := make(chan error, 72)
	for i := 0; i < 72; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			_, err := pool.evaluate(ctx, []secLangFile{{Name: "a.conf", Source: `SecAction "id:1,phase:1,pass"`}}, secLangFixture{Variables: map[string][]string{"ARGS:q": {"safe"}}})
			outcomes <- err
		}()
	}
	workers.Wait()
	close(outcomes)
	rejected := 0
	for err := range outcomes {
		if errors.Is(err, errSecPoolCapacity) {
			rejected++
		}
	}
	if rejected != 8 {
		t.Fatalf("pending work was not limited to64: %d rejected", rejected)
	}
}
func TestSecLangWorkerExitCannotDiscardItsFinalBufferedResponse(t *testing.T) {
	pool := newSecLangPool(poolTestBinary(t), 1)
	defer pool.close()
	policy, err := prepareSecPoolPolicy([]secLangFile{{Name: "a.conf", Source: `SecAction "id:1,phase:1,pass"`}})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	worker, err := pool.start(ctx, policy)
	if err != nil {
		t.Fatal(err)
	}
	defer worker.stop()
	raw, _ := json.Marshal(secLangFixture{Variables: map[string][]string{"ARGS:q": {"safe"}}})
	for n := 1; n < secStreamRequestLimit; n++ {
		if _, err = worker.exchange(ctx, raw); err != nil {
			t.Fatal(err)
		}
	}
	if err = writeSecFrame(worker.stdin, raw); err != nil {
		t.Fatal(err)
	}
	select {
	case <-worker.done:
	case <-ctx.Done():
		t.Fatal("worker did not finish its request limit")
	}
	response, err := readSecFrame(worker.stdout, 2<<20)
	if err != nil {
		t.Fatalf("final response lost after process exit: %v", err)
	}
	var result secStreamResponse
	if json.Unmarshal(response, &result) != nil || result.Kind != "RESULT" || result.Sequence != secStreamRequestLimit {
		t.Fatalf("final response incomplete: %s", response)
	}
}
