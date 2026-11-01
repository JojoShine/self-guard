package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDurableStateLifecycle(t *testing.T) {
	p := filepath.Join(t.TempDir(), "marker.json")
	if e := writePrivate(p, map[string]string{"status": "pending"}); e != nil {
		t.Fatal(e)
	}
	if e := writePrivate(p, map[string]string{"status": "updated"}); e != nil {
		t.Fatal(e)
	}
	var result map[string]string
	if e := read(p, &result); e != nil || result["status"] != "updated" {
		t.Fatal(e, result)
	}
	if e := removeDurable(p); e != nil {
		t.Fatal(e)
	}
	if _, e := os.Stat(p); !os.IsNotExist(e) {
		t.Fatal("marker remains")
	}
}
