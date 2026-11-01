package main

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os/exec"
	"time"
)

type secBoundedBuffer struct {
	bytes.Buffer
	limit int
}

func (b *secBoundedBuffer) Write(p []byte) (int, error) {
	if b.Len()+len(p) > b.limit {
		return 0, errors.New("worker output limit")
	}
	return b.Buffer.Write(p)
}
func runSecLangWorker(parent context.Context, binary string, input []byte, evaluate bool) (json.RawMessage, error) {
	if len(input) > 4<<20 {
		return nil, errors.New("worker input limit exceeded")
	}
	ctx, cancel := context.WithTimeout(parent, 2*time.Second)
	defer cancel()
	argument := "--check-seclang"
	if evaluate {
		argument = "--test-seclang"
	}
	command := exec.CommandContext(ctx, binary, argument)
	command.Env = []string{"PATH=/usr/bin:/bin", "GOMAXPROCS=1", "GOMEMLIMIT=128MiB"}
	command.Stdin = bytes.NewReader(input)
	output := &secBoundedBuffer{limit: 2 << 20}
	diagnostic := &secBoundedBuffer{limit: 8192}
	command.Stdout = output
	command.Stderr = diagnostic
	if err := command.Run(); err != nil {
		if ctx.Err() != nil {
			return nil, errors.New("rule worker exceeded execution deadline")
		}
		if diagnostic.Len() > 0 {
			return nil, errors.New(diagnostic.String())
		}
		return nil, errors.New("rule worker failed or exceeded resource budget")
	}
	if !json.Valid(output.Bytes()) {
		return nil, errors.New("rule worker returned invalid output")
	}
	return append(json.RawMessage{}, output.Bytes()...), nil
}

var secWorkerSlots = make(chan struct{}, 4)

type secLangHTTPHandler struct {
	token, binary string
	evaluate      bool
	slots         chan struct{}
	pool          *secLangPool
}

func newSecLangHTTPHandler(token string, evaluate bool, binary string) *secLangHTTPHandler {
	handler := &secLangHTTPHandler{token: token, binary: binary, evaluate: evaluate, slots: make(chan struct{}, 1)}
	if evaluate {
		handler.pool = newSecLangPool(binary, 1)
	}
	return handler
}
func newSecLangManagementHandlers(token, binary string) (*secLangHTTPHandler, *secLangHTTPHandler) {
	check, evaluate := newSecLangHTTPHandler(token, false, binary), newSecLangHTTPHandler(token, true, binary)
	// One reserved management permit serves both operations. A check first
	// relinquishes the idle testing process, leaving all live workers intact.
	check.slots, check.pool = evaluate.slots, evaluate.pool
	return check, evaluate
}
func (h *secLangHTTPHandler) Close() {
	if h.pool != nil {
		h.pool.close()
	}
}
func (h *secLangHTTPHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h.token == "" || subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+h.token)) != 1 {
		http.Error(w, "component identity required", 401)
		return
	}
	if r.Method != "POST" {
		http.Error(w, "POST required", 405)
		return
	}
	select {
	case h.slots <- struct{}{}:
		defer func() { <-h.slots }()
	default:
		w.Header().Set("Retry-After", "2")
		http.Error(w, "rule worker capacity reached", 429)
		return
	}
	input, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 4<<20))
	if err != nil {
		http.Error(w, "rule package exceeds limit", 413)
		return
	}
	if h.binary == "" {
		http.Error(w, "worker unavailable", 503)
		return
	}
	var result json.RawMessage
	if h.evaluate {
		var fixture secLangFixture
		fixture, err = decodeSecFixture(input)
		if err == nil && fixture.Request != nil {
			err = errors.New("observed requests are internal runtime transport only")
		}
		if err == nil {
			files := fixture.Files
			fixture.Files = nil
			var decision secResult
			decision, err = h.pool.evaluate(r.Context(), files, fixture)
			if err == nil {
				result, err = json.Marshal(decision)
			}
		}
	} else {
		if h.pool != nil {
			h.pool.discardIdle()
		}
		select {
		case secWorkerSlots <- struct{}{}:
			defer func() { <-secWorkerSlots }()
		default:
			w.Header().Set("Retry-After", "2")
			http.Error(w, "rule worker capacity reached", http.StatusTooManyRequests)
			return
		}
		result, err = runSecLangWorker(r.Context(), h.binary, input, false)
	}
	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		if errors.Is(err, errSecPoolCapacity) {
			w.Header().Set("Retry-After", "2")
			w.WriteHeader(429)
		} else {
			w.WriteHeader(422)
		}
		json.NewEncoder(w).Encode(map[string]string{"message": err.Error(), "status": "INCOMPLETE"})
		return
	}
	w.Write(result)
}
