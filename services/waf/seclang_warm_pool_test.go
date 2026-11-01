package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestWarmedPoolReplenishesRetiredWorkerWithoutColdStartingNextRequest(t *testing.T) {
	binary := poolTestBinary(t)
	wrapper := filepath.Join(t.TempDir(), "cold-start-worker")
	command := "#!/bin/sh\nsleep 0.25\nexec '" + strings.ReplaceAll(binary, "'", "'\\''") + "' \"$@\"\n"
	if err := os.WriteFile(wrapper, []byte(command), 0700); err != nil {
		t.Fatal(err)
	}
	pool := newSecLangPool(wrapper, 3)
	defer pool.close()
	policy, _ := prepareSecPoolPolicy([]secLangFile{{Name: "warm.conf", Source: `SecRule ARGS:q "@contains attack" "id:42120,phase:2,deny"`}})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := pool.warmPolicy(ctx, policy); err != nil {
		t.Fatal(err)
	}
	if pool.stats() != 3 {
		t.Fatal("activation did not prepare three bounded workers")
	}
	for index := 0; index < secStreamRequestLimit; index++ {
		result, err := pool.evaluatePolicy(context.Background(), policy, secLangFixture{Variables: map[string][]string{"ARGS:q": {"attack"}}})
		if err != nil || !result.Blocked {
			t.Fatalf("request %d: %+v %v", index, result, err)
		}
	}
	started := time.Now()
	result, err := pool.evaluatePolicy(context.Background(), policy, secLangFixture{Variables: map[string][]string{"ARGS:q": {"safe"}}})
	if err != nil || result.Blocked || time.Since(started) >= 200*time.Millisecond {
		t.Fatalf("next request waited for deliberate 250ms cold initialization: %+v %v", result, err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		pool.mu.Lock()
		ready := 0
		for _, slot := range pool.slots {
			if !slot.busy && slot.worker != nil && slot.digest == policy.digest {
				ready++
			}
		}
		pool.mu.Unlock()
		if ready == 3 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("retired slot was not replenished")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if pool.stats() != 4 {
		t.Fatal("replenishment created excess workers")
	}
	pool.mu.Lock()
	for _, slot := range pool.slots {
		if slot.worker.requests >= secStreamRequestLimit {
			t.Error("retired process was reused beyond its request limit")
		}
	}
	pool.mu.Unlock()
}

func TestWarmedPoolShutdownCancelsReplenishmentAndRejectsNewWork(t *testing.T) {
	pool := newSecLangPool(poolTestBinary(t), 3)
	policy, _ := prepareSecPoolPolicy([]secLangFile{{Name: "warm.conf", Source: `SecAction "id:42121,phase:1,pass"`}})
	if err := pool.warmPolicy(context.Background(), policy); err != nil {
		pool.close()
		t.Fatal(err)
	}
	for index := 0; index < secStreamRequestLimit; index++ {
		if _, err := pool.evaluatePolicy(context.Background(), policy, secLangFixture{Variables: map[string][]string{}}); err != nil {
			pool.close()
			t.Fatal(err)
		}
	}
	done := make(chan struct{})
	go func() { pool.close(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("background initialization survived pool shutdown")
	}
	if err := pool.warmPolicy(context.Background(), policy); err == nil {
		t.Fatal("closed pool accepted activation")
	}
	if len(secWorkerSlots) != 0 {
		t.Fatal("worker process permits leaked after shutdown")
	}
}
