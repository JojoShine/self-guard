package main

import (
	"context"
	"encoding/json"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSecLangWorkerRunsRealChildWithBoundedInputAndDeadline(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "waf-worker")
	build := exec.Command("go", "build", "-o", binary, ".")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v %s", err, output)
	}
	payload := []byte(`{"files":[{"name":"rules.conf","source":"SecRule ARGS:q \"@contains attack\" \"id:1001,phase:2,deny\""}],"variables":{"ARGS:q":["attack"]},"threshold":5}`)
	raw, err := runSecLangWorker(context.Background(), binary, payload, true)
	if err != nil {
		t.Fatal(err)
	}
	var result secResult
	if err = json.Unmarshal(raw, &result); err != nil || !result.Blocked {
		t.Fatalf("%s %v", raw, err)
	}
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	if _, err = runSecLangWorker(ctx, binary, payload, true); err == nil {
		t.Fatal("cancelled worker accepted")
	}
	if _, err = runSecLangWorker(context.Background(), binary, []byte(strings.Repeat(" ", (4<<20)+1)), false); err == nil {
		t.Fatal("oversized worker payload accepted")
	}
}
