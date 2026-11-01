package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCollectorsPersist(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "watch")
	os.WriteFile(p, []byte("first\n"), 0600)
	a := &Agent{Config: Config{StateDir: d, FIMPaths: []string{p}, LogPaths: []string{p}}}
	f := a.collectFiles()
	a.commitCollectors()
	if len(f) != 1 {
		t.Fatalf("initial log: %d", len(f))
	}
	os.WriteFile(p, []byte("changed\nextra\n"), 0600)
	f = a.collectFiles()
	a.commitCollectors()
	if len(f) != 2 {
		t.Fatalf("change and log: %d", len(f))
	}
	b := &Agent{Config: a.Config}
	if f = b.collectFiles(); len(f) != 0 {
		t.Fatalf("replayed: %v", f)
	}
}
