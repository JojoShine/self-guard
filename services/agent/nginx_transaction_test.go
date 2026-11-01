package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNginxTransactionRestoresOnProbeFailure(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "site.conf")
	os.WriteFile(path, []byte("before"), 0640)
	calls := []string{}
	runner := func(args ...string) error { calls = append(calls, strings.Join(args, " ")); return nil }
	err := applyNginxTransaction(path, filepath.Join(dir, "transaction"), []byte("after"), contentDigest([]byte("before")), func() error { return os.ErrInvalid }, runner)
	b, _ := os.ReadFile(path)
	if err == nil || string(b) != "before" || len(calls) != 5 {
		t.Fatal(err, string(b), calls)
	}
	var state nginxTransaction
	read(filepath.Join(dir, "transaction", "journal.json"), &state)
	if state.Status != "ROLLED_BACK" {
		t.Fatal(state)
	}
}
func TestNginxTransactionCommitsAndRefusesConcurrentChanges(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "site.conf")
	os.WriteFile(path, []byte("before"), 0640)
	if err := applyNginxTransaction(path, filepath.Join(dir, "tx"), []byte("after"), contentDigest([]byte("before")), func() error { return nil }, func(...string) error { return nil }); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(path, []byte("external change"), 0640)
	if err := rollbackNginxTransaction(filepath.Join(dir, "tx"), func(...string) error { return nil }); err == nil {
		t.Fatal("overwrote external change")
	}
	b, _ := os.ReadFile(path)
	if string(b) != "external change" {
		t.Fatal(string(b))
	}
}

func TestNginxTransactionRefusesStalePlan(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "site.conf")
	os.WriteFile(path, []byte("new external version"), 0640)
	if err := applyNginxTransaction(path, filepath.Join(dir, "tx"), []byte("planned version"), contentDigest([]byte("old source")), func() error { return nil }, func(...string) error { return nil }); err == nil {
		t.Fatal("stale source overwritten")
	}
	b, _ := os.ReadFile(path)
	if string(b) != "new external version" {
		t.Fatal(string(b))
	}
}
