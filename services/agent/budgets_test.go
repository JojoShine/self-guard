package main

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestPayloadRateAndCancel(t *testing.T) {
	r := &pacedReader{reader: strings.NewReader("1234"), ctx: context.Background(), rate: 100}
	start := time.Now()
	b := make([]byte, 10)
	n, e := r.Read(b)
	if e != nil || n != 4 || time.Since(start) < 35*time.Millisecond {
		t.Fatal(n, e, "payload not paced")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r = &pacedReader{reader: strings.NewReader("x"), ctx: ctx, rate: 1}
	if _, e = r.Read(b); e == nil {
		t.Fatal("cancel ignored")
	}
}
func TestQueueByteBudget(t *testing.T) {
	a := &Agent{Config: Config{StateDir: t.TempDir(), MaxQueueBytes: 10}}
	if a.heartbeat(map[string]string{"long": "inventory"}, nil) == nil || len(a.Queue) != 0 {
		t.Fatal("heartbeat exceeded queue budget")
	}
	if a.enqueue("/test", strings.Repeat("x", 20)) == nil || len(a.Queue) != 0 {
		t.Fatal("enqueue exceeded queue budget")
	}
}
