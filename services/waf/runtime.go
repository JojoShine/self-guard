package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

func validPolicyPath(path string) bool {
	u, err := url.ParseRequestURI(path)
	return err == nil && strings.HasPrefix(path, "/") && !strings.HasPrefix(path, "//") && u.RawQuery == "" && u.Fragment == "" && u.Path == path
}
func (e *engine) rateExceeded(key string, limit int) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	now := time.Now()
	c := e.rates[key]
	if now.After(c.until) {
		c = counter{until: now.Add(time.Minute)}
	}
	if len(e.rates) >= 10000 {
		for k, v := range e.rates {
			if now.After(v.until) {
				delete(e.rates, k)
			}
		}
	}
	if _, exists := e.rates[key]; !exists && len(e.rates) >= 10000 {
		return true
	}
	c.n++
	e.rates[key] = c
	return c.n > limit
}

type statusWriter struct {
	http.ResponseWriter
	status int
	wrote  bool
}

func (w *statusWriter) WriteHeader(status int) {
	if !w.wrote {
		w.status = status
		w.wrote = true
	}
	w.ResponseWriter.WriteHeader(status)
}
func (w *statusWriter) Write(b []byte) (int, error) {
	if !w.wrote {
		w.WriteHeader(200)
	}
	return w.ResponseWriter.Write(b)
}
func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// Preserve streaming support through the reverse proxy.
func (w *statusWriter) Flush() {
	if !w.wrote {
		w.WriteHeader(200)
	}
	_ = http.NewResponseController(w.ResponseWriter).Flush()
}
func safeMethod(method string) string {
	if contains([]string{"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "CONNECT", "TRACE"}, method) {
		return method
	}
	return "OTHER"
}

type AccessEntry struct {
	Context        *requestTrace `json:"context,omitempty"`
	ID             string        `json:"id"`
	SiteID         string        `json:"siteId"`
	Method         string        `json:"method"`
	Path           string        `json:"path"`
	Status         int           `json:"status"`
	Timestamp      string        `json:"timestamp"`
	DurationMicros int64         `json:"durationMicros"`
}
type accessLog struct {
	mu       sync.Mutex
	path     string
	capacity int
	items    []AccessEntry
	encoded  [][]byte
	evicted  uint64
}

func openAccessLog(dir string, capacity int) (*accessLog, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	a := &accessLog{path: filepath.Join(dir, "access.json"), capacity: capacity}
	f, err := os.Open(a.path)
	if os.IsNotExist(err) {
		return a, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, 8<<20))
	if err != nil {
		return nil, err
	}
	if err = json.Unmarshal(b, &a.items); err != nil {
		return nil, err
	}
	if len(a.items) > capacity {
		return nil, fmt.Errorf("access log exceeds capacity")
	}
	// Preserve old retained history during upgrades; persist assigned IDs before
	// publishing it so central upserts remain stable over subsequent restarts.
	migrated := false
	hostname, _ := os.Hostname()
	for i := range a.items {
		if a.items[i].ID == "" {
			digest := sha256.Sum256([]byte(fmt.Sprintf("%s:%d:%s", env("WAF_NODE_ID", hostname), i, b)))
			a.items[i].ID = fmt.Sprintf("legacy:%x", digest)
			migrated = true
		}
	}
	if migrated {
		data, err := json.Marshal(a.items)
		if err != nil {
			return nil, err
		}
		if err = persistConfig(a.path, data); err != nil {
			return nil, err
		}
	}
	return a, nil
}
func (a *accessLog) append(entry AccessEntry) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	// Rows are immutable owned JSON. Preserve the exact snapshot format and
	// synchronous persistence while encoding only the new observation.
	if len(a.encoded) != len(a.items) {
		a.encoded = make([][]byte, 0, len(a.items))
		for _, retained := range a.items {
			raw, err := json.Marshal(retained)
			if err != nil {
				return err
			}
			a.encoded = append(a.encoded, raw)
		}
	}
	raw, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	evicted := len(a.items)+1 > a.capacity
	start := 0
	if evicted {
		start = len(a.items) + 1 - a.capacity
	}
	encoded := make([][]byte, 0, min(len(a.items)+1, a.capacity))
	if start < len(a.items) {
		encoded = append(encoded, a.encoded[start:]...)
	}
	if a.capacity > 0 {
		encoded = append(encoded, raw)
	}
	size := 2
	for index, row := range encoded {
		size += len(row)
		if index > 0 {
			size++
		}
	}
	data := make([]byte, 0, size)
	data = append(data, '[')
	for index, row := range encoded {
		if index > 0 {
			data = append(data, ',')
		}
		data = append(data, row...)
	}
	data = append(data, ']')
	if err = persistConfig(a.path, data); err != nil {
		return err
	}
	next := make([]AccessEntry, 0, len(encoded))
	if start < len(a.items) {
		next = append(next, a.items[start:]...)
	}
	if a.capacity > 0 {
		next = append(next, entry)
	}
	a.items = next
	a.encoded = encoded
	if evicted {
		a.evicted++
	}
	return nil
}

type UpstreamHealth struct {
	SiteID     string `json:"siteId"`
	Healthy    bool   `json:"healthy"`
	StatusCode int    `json:"statusCode"`
	CheckedAt  string `json:"checkedAt"`
}

func (e *engine) checkUpstreams() {
	sites := e.sites.Load().(map[string]runtimeSite)
	jobs := make(chan runtimeSite)
	results := make(chan UpstreamHealth, len(sites))
	var wg sync.WaitGroup
	transport := &http.Transport{Proxy: nil}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for s := range jobs {
				u, _ := url.Parse(s.Upstream)
				u.Path = s.Config.HealthCheckPath
				u.RawPath = ""
				u.RawQuery = ""
				result := UpstreamHealth{SiteID: s.ID, CheckedAt: time.Now().UTC().Format(time.RFC3339)}
				resp, err := client.Get(u.String())
				if err == nil {
					result.StatusCode = resp.StatusCode
					result.Healthy = resp.StatusCode >= 200 && resp.StatusCode < 400
					resp.Body.Close()
				}
				results <- result
			}
		}()
	}
	for _, s := range sites {
		if s.Enabled {
			jobs <- s
		}
	}
	close(jobs)
	wg.Wait()
	close(results)
	health := []UpstreamHealth{}
	for result := range results {
		health = append(health, result)
	}
	e.health.Store(health)
}

// Copy under the log lock; encoding and the management request never hold it.
func (a *accessLog) snapshot() ([]AccessEntry, int, uint64) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]AccessEntry{}, a.items...), a.capacity, a.evicted
}
func (e *engine) heartbeatPayload() map[string]any {
	sites := []map[string]any{}
	for _, s := range e.sites.Load().(map[string]runtimeSite) {
		ack := map[string]any{"id": s.ID, "version": s.Version}
		if s.RuleRelease != nil {
			raw, _ := base64.StdEncoding.DecodeString(s.RuleRelease.Payload)
			ack["ruleReleaseSha256"] = fmt.Sprintf("%x", sha256.Sum256(raw))
		}
		sites = append(sites, ack)
	}
	history := []AccessEntry{}
	capacity := 0
	var evicted uint64
	if e.access != nil {
		history, capacity, evicted = e.access.snapshot()
	}
	return map[string]any{
		"nodeId": e.nodeID, "version": "0.1.0", "sites": sites, "startedAt": e.startedAt,
		"droppedEvents": e.dropped.Load(), "totalRequests": e.totalRequests.Load(), "blockedRequests": e.blockedRequests.Load(), "observedRequests": e.observedRequests.Load(), "upstreamErrors": e.upstreamErrors.Load(), "accessLogDropped": e.accessLogDropped.Load(), "upstreamHealth": e.health.Load(),
		"accessHistory": history, "accessHistoryCapacity": capacity, "accessHistoryCount": len(history), "accessHistoryEvictedSinceStart": evicted,
	}
}
