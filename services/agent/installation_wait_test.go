package main

import (
	"errors"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestExecutorWaitsForBriefInstallationCommitButDoesNotWaitForever(t *testing.T) {
	path := filepath.Join(t.TempDir(), "operation.lock")
	unlock, err := lockInstallationFile(path)
	if err != nil {
		t.Fatal(err)
	}
	released := make(chan struct{})
	go func() { time.Sleep(50 * time.Millisecond); unlock(); close(released) }()
	next, err := waitInstallationFile(path, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-released:
	default:
		t.Fatal("mutation entered before installation released its lock")
	}
	defer next()
	if again, err := waitInstallationFile(path, 20*time.Millisecond); err == nil {
		again()
		t.Fatal("unbounded parallel entry")
	} else if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EAGAIN) {
		t.Fatal("unexpected wait failure", err)
	}
}
