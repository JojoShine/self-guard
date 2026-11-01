package main

import (
	"context"
	"io"
	"runtime"
	"runtime/debug"
	"time"
)

// These are cooperative process and payload limits, not OS cgroup CPU quotas.
func applyResourceBudgets(c Config) {
	if c.MaxCPUs > 0 {
		runtime.GOMAXPROCS(c.MaxCPUs)
	}
	if c.MaxMemoryBytes > 0 {
		debug.SetMemoryLimit(c.MaxMemoryBytes)
	}
}

type pacedReader struct {
	reader io.Reader
	ctx    context.Context
	rate   int64
}

func (r *pacedReader) Read(p []byte) (int, error) {
	if len(p) > 4096 {
		p = p[:4096]
	}
	n, e := r.reader.Read(p)
	if n > 0 && r.rate > 0 {
		delay := time.Duration(int64(n) * int64(time.Second) / r.rate)
		timer := time.NewTimer(delay)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-r.ctx.Done():
			return 0, r.ctx.Err()
		}
	}
	return n, e
}
