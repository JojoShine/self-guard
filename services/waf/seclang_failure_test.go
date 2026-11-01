package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestInspectionFailureKindIsBoundedAndDoesNotExposeWorkerDetails(t *testing.T) {
	for _, row := range []struct {
		err  error
		kind string
	}{
		{nil, ""}, {errSecPoolCapacity, "QUEUE_CAPACITY"},
		{secFailure("REQUEST_INCOMPLETE", errors.New("secret submitted content")), "REQUEST_INCOMPLETE"},
		{fmt.Errorf("wrapped: %w", secFailure("WORKER_PROTOCOL", errors.New("private child output"))), "WORKER_PROTOCOL"},
		{context.Canceled, "CANCELLED"}, {errors.New("secret submitted content"), "INSPECTION_INCOMPLETE_OR_UNAVAILABLE"},
	} {
		if got := secFailureKind(row.err); got != row.kind {
			t.Fatalf("kind %q, want %q", got, row.kind)
		}
		site := runtimeSite{Site: Site{Upstream: "https://app.test"}, rulePolicy: &secRuntimePolicy{}}
		proof := secInspectionEvent("edge", site, secResult{}, row.err)
		if proof.FailureKind != row.kind || proof.Complete != (row.err == nil) {
			t.Fatalf("incorrect failure proof: %+v", proof)
		}
	}
}

func TestPoolReportsActualDeadlineStageAndParsingFailure(t *testing.T) {
	sleeper := filepath.Join(t.TempDir(), "worker")
	if err := os.WriteFile(sleeper, []byte("#!/bin/sh\nexec sleep 30\n"), 0700); err != nil {
		t.Fatal(err)
	}
	pool := newSecLangPool(sleeper, 1)
	defer pool.close()
	policy, _ := prepareSecPoolPolicy([]secLangFile{{Name: "a.conf", Source: `SecAction "id:1,phase:1,pass"`}})
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err := pool.evaluatePolicy(ctx, policy, secLangFixture{Variables: map[string][]string{}})
	if secFailureKind(err) != "WORKER_DEADLINE" || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("lost initialization deadline: %v", err)
	}
	// A busy slot times out before any process is started; distinguish this from execution.
	queued := newSecLangPool(sleeper, 1)
	defer queued.close()
	queued.slots[0].busy = true
	ctx2, cancel2 := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel2()
	_, err = queued.evaluatePolicy(ctx2, policy, secLangFixture{Variables: map[string][]string{}})
	if secFailureKind(err) != "QUEUE_TIMEOUT" {
		t.Fatalf("incorrect queue diagnosis: %v", err)
	}
	actual := newSecLangPool(poolTestBinary(t), 1)
	defer actual.close()
	_, err = actual.evaluatePolicy(context.Background(), policy, secLangFixture{RequestBase64: "AA=="})
	if secFailureKind(err) != "REQUEST_INCOMPLETE" {
		t.Fatalf("invalid request became process outage: %v", err)
	}
}
