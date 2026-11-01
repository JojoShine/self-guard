package main

import (
	"errors"
	"strings"
	"testing"
)

func TestPackageCollectionCompleteness(t *testing.T) {
	w := &cappedOutput{}
	w.Write([]byte("pkg\t1\n"))
	lines, status := packageLines(w, nil)
	if len(lines) != 1 || !status.Complete {
		t.Fatal(status)
	}
	_, status = packageLines(w, errors.New("failed"))
	if status.Complete {
		t.Fatal("error complete")
	}
	w = &cappedOutput{}
	w.Write([]byte(strings.Repeat("p\t1\n", 70000)))
	_, status = packageLines(w, nil)
	if !w.truncated || status.Complete {
		t.Fatal("truncation complete")
	}
	w = &cappedOutput{}
	w.Write([]byte(strings.Repeat("p\t1\n", 2001)))
	lines, status = packageLines(w, nil)
	if len(lines) != 2000 || status.Complete {
		t.Fatal("cap complete")
	}
}
