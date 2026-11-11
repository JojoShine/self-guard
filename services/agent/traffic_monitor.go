package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"
)

const trafficMonitorMaxSequence = 2147483647

type TrafficMonitorConfig struct {
	Schema    string               `json:"schema"`
	MonitorID string               `json:"monitorId"`
	AssetID   string               `json:"assetId"`
	Capture   TrafficCaptureConfig `json:"capture"`
	StateDir  string               `json:"stateDir"`
}

func (c *TrafficMonitorConfig) validate() error {
	uuid := regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	if c.Schema != "selfguard-traffic-monitor-config-v1" || !uuid.MatchString(c.MonitorID) || !uuid.MatchString(c.AssetID) || c.StateDir != "/var/lib/selfguard-traffic-monitor" {
		return errors.New("invalid traffic monitor identity or state directory")
	}
	if c.Capture.DurationSeconds == 0 {
		c.Capture.DurationSeconds = 60
	}
	if c.Capture.IncludePayload || c.Capture.SnapLen != 128 || c.Capture.RetentionHours != 0 {
		return errors.New("traffic monitor requires metadata only, snapLen 128 and no retention")
	}
	return c.Capture.validate()
}

type TrafficMonitorReport struct {
	Schema         string          `json:"schema"`
	MonitorID      string          `json:"monitorId"`
	Status         string          `json:"status"`
	Sequence       int64           `json:"sequence"`
	UpdatedAt      time.Time       `json:"updatedAt"`
	Summary        *TrafficSummary `json:"summary,omitempty"`
	Detail         string          `json:"detail"`
	DroppedWindows int             `json:"droppedWindows"`
}
type trafficMonitorState struct {
	MonitorID      string                 `json:"monitorId"`
	Sequence       int64                  `json:"sequence"`
	DroppedWindows int                    `json:"droppedWindows"`
	Active         bool                   `json:"active"`
	Pending        []TrafficMonitorReport `json:"pending"`
}
type trafficMonitorQueue struct {
	mu      sync.Mutex
	path    string
	state   trafficMonitorState
	failure error
}

func loadTrafficMonitorQueue(path, id string) (*trafficMonitorQueue, error) {
	q := &trafficMonitorQueue{path: path, state: trafficMonitorState{MonitorID: id}}
	b, err := readBoundedFile(path, 8<<20)
	if os.IsNotExist(err) {
		return q, nil
	}
	if err != nil {
		return nil, err
	}
	if err = decodeExecutorParameters(b, &q.state); err != nil {
		return nil, err
	}
	if q.state.MonitorID != id || q.state.Sequence < 0 || q.state.Sequence > trafficMonitorMaxSequence || q.state.DroppedWindows < 0 || q.state.DroppedWindows > trafficMonitorMaxSequence || len(q.state.Pending) > 64 {
		return nil, errors.New("invalid traffic monitor persisted state")
	}
	var previous int64
	for _, r := range q.state.Pending {
		if r.MonitorID != id || r.Sequence <= previous || r.Sequence > q.state.Sequence {
			return nil, errors.New("invalid traffic monitor queue sequence")
		}
		previous = r.Sequence
	}
	return q, nil
}
func (q *trafficMonitorQueue) enqueue(status string, s *TrafficSummary, detail string) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.failure != nil {
		return q.failure
	}
	if q.state.Sequence >= trafficMonitorMaxSequence {
		return errors.New("traffic monitor sequence exhausted")
	}
	next := q.state
	next.Pending = append([]TrafficMonitorReport(nil), q.state.Pending...)
	next.Sequence++
	if ((s == nil && (status == "RUNNING" || status == "STOPPED")) || status == "FAILED") && next.Active {
		if next.DroppedWindows >= trafficMonitorMaxSequence {
			return errors.New("traffic monitor loss counter exhausted")
		}
		next.DroppedWindows++
	}
	next.Active = status == "RUNNING"
	if len(detail) > 500 {
		detail = detail[:500]
	}
	r := TrafficMonitorReport{Schema: "selfguard-traffic-monitor-v1", MonitorID: next.MonitorID, Status: status, Sequence: next.Sequence, UpdatedAt: time.Now().UTC(), Summary: s, Detail: detail}
	next.Pending = append(next.Pending, r)
	for {
		next.Pending[len(next.Pending)-1].DroppedWindows = next.DroppedWindows
		b, err := json.Marshal(next)
		if err != nil {
			return err
		}
		if len(next.Pending) <= 64 && len(b) <= 8<<20 {
			break
		}
		if next.DroppedWindows == trafficMonitorMaxSequence {
			return errors.New("traffic monitor loss counter exhausted")
		}
		if next.Pending[0].Summary != nil {
			next.DroppedWindows++
		}
		next.Pending = next.Pending[1:]
	}
	if err := writePrivate(q.path, next); err != nil {
		q.failure = err
		return err
	}
	q.state = next
	return nil
}
func (q *trafficMonitorQueue) first() *TrafficMonitorReport {
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.state.Pending) == 0 {
		return nil
	}
	r := q.state.Pending[0]
	return &r
}
func (q *trafficMonitorQueue) ack(seq int64) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.failure != nil {
		return q.failure
	}
	next := q.state
	next.Pending = append([]TrafficMonitorReport(nil), q.state.Pending...)
	for len(next.Pending) > 0 && next.Pending[0].Sequence <= seq {
		next.Pending = next.Pending[1:]
	}
	if err := writePrivate(q.path, next); err != nil {
		q.failure = err
		return err
	}
	q.state = next
	return nil
}

type trafficMonitorWindow struct {
	summary       *TrafficSummary
	deadline      time.Time
	examinedBytes int
}

func newTrafficMonitorWindow(c TrafficCaptureConfig, now time.Time) *trafficMonitorWindow {
	return &trafficMonitorWindow{summary: newTrafficSummary(c, now), deadline: now.Add(time.Duration(c.DurationSeconds) * time.Second)}
}
func (w *trafficMonitorWindow) consume(b []byte, now time.Time) {
	s := w.summary
	c := s.Scope
	if s.StopReason != "" {
		return
	}
	if s.Packets >= c.MaxPackets {
		s.StopReason = "PACKET_LIMIT"
		return
	}
	s.ExaminedPackets++
	w.examinedBytes += len(b)
	s.consume(b, now, io.Discard)
	if s.StopReason != "" {
		return
	}
	if s.Packets >= c.MaxPackets {
		s.StopReason = "PACKET_LIMIT"
	} else if s.CapturedBytes+c.SnapLen > c.MaxBytes {
		s.StopReason = "BYTE_LIMIT"
	} else if s.ExaminedPackets >= 200000 || w.examinedBytes >= 128<<20 {
		s.StopReason = "EXAMINATION_LIMIT"
	}
}
func (w *trafficMonitorWindow) roll(now time.Time, stop bool) *TrafficSummary {
	if !stop && now.Before(w.deadline) {
		return nil
	}
	s := w.summary
	s.EndedAt = now.UTC()
	if s.StopReason == "" {
		s.StopReason = "WINDOW_ELAPSED"
		if stop {
			s.StopReason = "MONITOR_STOPPED"
		}
	}
	s.Complete = (s.StopReason == "WINDOW_ELAPSED" || s.StopReason == "MONITOR_STOPPED") && s.SocketDropped == 0
	*w = *newTrafficMonitorWindow(s.Scope, now)
	return s
}

type trafficMonitorHTTPError int

func (e trafficMonitorHTTPError) Error() string {
	return fmt.Sprintf("monitor server status %d", int(e))
}
func monitorRevoked(err error) bool {
	var s trafficMonitorHTTPError
	return errors.As(err, &s) && (s == 401 || s == 403 || s == 404)
}
func monitorRequest(ctx context.Context, a *Agent, method, path string, body, out any) error {
	var b []byte
	var err error
	if body != nil {
		b, err = json.Marshal(body)
		if err != nil {
			return err
		}
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(a.Config.Server, "/")+"/api"+path, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+a.Identity.Token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := a.Client.Do(req)
	if err != nil {
		return errors.New("monitor server unavailable")
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return trafficMonitorHTTPError(resp.StatusCode)
	}
	if out != nil {
		return json.NewDecoder(io.LimitReader(resp.Body, 16<<10)).Decode(out)
	}
	return nil
}
func monitorDesiredState(ctx context.Context, a *Agent, c TrafficMonitorConfig) (bool, error) {
	var control struct {
		MonitorID    string `json:"monitorId"`
		AssetID      string `json:"assetId"`
		DesiredState string `json:"desiredState"`
	}
	err := monitorRequest(ctx, a, "GET", "/agent/traffic-monitor/"+c.MonitorID, nil, &control)
	if err != nil {
		return false, err
	}
	if control.MonitorID != c.MonitorID || control.AssetID != c.AssetID || (control.DesiredState != "RUNNING" && control.DesiredState != "STOPPED") {
		return false, errors.New("invalid traffic monitor control response")
	}
	return control.DesiredState == "STOPPED", nil
}
func deliverTrafficMonitor(ctx context.Context, a *Agent, q *trafficMonitorQueue) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	// Bound work per pass; failures remain durable with the same sequence for deduplication.
	for i := 0; i < 64; i++ {
		r := q.first()
		if r == nil {
			return nil
		}
		if err := monitorRequest(ctx, a, "POST", "/agent/network-report", r, nil); err != nil {
			return err
		}
		if err := q.ack(r.Sequence); err != nil {
			return err
		}
	}
	return nil
}

// Revocation invalidates queued authorization, so obsolete windows must not
// block the separately authorized terminal observation. Persist loss explicitly.
func stopRevokedTrafficMonitor(a *Agent, q *trafficMonitorQueue) error {
	q.mu.Lock()
	if q.failure != nil {
		err := q.failure
		q.mu.Unlock()
		return err
	}
	next := q.state
	lost := 0
	if next.Active {
		lost++
	}
	for _, r := range next.Pending {
		if r.Summary != nil {
			lost++
		}
	}
	if next.Sequence >= trafficMonitorMaxSequence || lost > trafficMonitorMaxSequence-next.DroppedWindows {
		q.mu.Unlock()
		return errors.New("traffic monitor terminal counters exhausted")
	}
	next.Sequence++
	next.DroppedWindows += lost
	next.Active = false
	next.Pending = []TrafficMonitorReport{{Schema: "selfguard-traffic-monitor-v1", MonitorID: next.MonitorID, Status: "STOPPED", Sequence: next.Sequence, UpdatedAt: time.Now().UTC(), Detail: "authorization revoked; queued windows discarded and monitoring stopped", DroppedWindows: next.DroppedWindows}}
	if err := writePrivate(q.path, next); err != nil {
		q.failure = err
		q.mu.Unlock()
		return err
	}
	q.state = next
	q.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// Revocation is terminal even when the token or monitor no longer exists.
	// An undelivered terminal report stays durable for later reconciliation.
	_ = deliverTrafficMonitor(ctx, a, q)
	return nil
}

func runTrafficMonitor(configFile string) error {
	if err := executorPlatform(); err != nil {
		return err
	}
	if err := executorTrustedConfig(configFile); err != nil {
		return err
	}
	info, err := os.Stat(configFile)
	if err != nil {
		return err
	}
	if info.Mode().Perm() != 0600 {
		return errors.New("traffic monitor config must be mode 0600")
	}
	b, err := readBoundedFile(configFile, 16<<10)
	if err != nil {
		return err
	}
	var c TrafficMonitorConfig
	if err = decodeExecutorParameters(b, &c); err != nil {
		return err
	}
	if err = c.validate(); err != nil {
		return err
	}
	a, err := hostNetworkAgent()
	if err != nil {
		return err
	}
	if c.AssetID != a.Identity.AssetID {
		return errors.New("traffic monitor asset does not match registered identity")
	}
	if err = executorTrustedDirectory(filepath.Dir(c.StateDir), false); err != nil {
		return err
	}
	if err = os.MkdirAll(c.StateDir, 0700); err != nil {
		return err
	}
	if err = executorTrustedDirectory(c.StateDir, true); err != nil {
		return err
	}
	unlock, err := lockTrafficMonitor(filepath.Join(c.StateDir, c.MonitorID+".lock"))
	if err != nil {
		return err
	}
	defer unlock()
	path := filepath.Join(c.StateDir, c.MonitorID+".json")
	if _, err = os.Lstat(path); err == nil {
		if err = executorTrustedConfig(path); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	q, err := loadTrafficMonitorQueue(path, c.MonitorID)
	if err != nil {
		return err
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	return runTrafficMonitorSession(ctx, a, c, q, captureTrafficMonitor)
}

func runTrafficMonitorSession(ctx context.Context, a *Agent, c TrafficMonitorConfig, q *trafficMonitorQueue, capture func(context.Context, TrafficCaptureConfig, func(*TrafficSummary) error) error) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var err error
	stop, controlErr := monitorDesiredState(ctx, a, c)
	if monitorRevoked(controlErr) {
		return stopRevokedTrafficMonitor(a, q)
	}
	if stop {
		if err = q.enqueue("STOPPED", nil, "monitor stopped by server before capture"); err != nil {
			return err
		}
		deliveryErr := deliverTrafficMonitor(ctx, a, q)
		if monitorRevoked(deliveryErr) {
			return stopRevokedTrafficMonitor(a, q)
		}
		return deliveryErr
	}
	if err = q.enqueue("RUNNING", nil, "continuous metadata monitoring started"); err != nil {
		return err
	}
	done := make(chan error, 1)
	wake := make(chan struct{}, 1)
	go func() {
		done <- capture(ctx, c.Capture, func(s *TrafficSummary) error {
			status := "RUNNING"
			if ctx.Err() != nil {
				status = "STOPPED"
			}
			err := q.enqueue(status, s, "metadata aggregation window")
			select {
			case wake <- struct{}{}:
			default:
			}
			return err
		})
	}()
	poll := time.NewTicker(time.Duration(c.Capture.DurationSeconds) * time.Second)
	defer poll.Stop()
	retry := time.NewTicker(5 * time.Second)
	defer retry.Stop()
	var captureErr error
	revoked := false
loop:
	for {
		select {
		case captureErr = <-done:
			break loop
		case <-ctx.Done():
			captureErr = <-done
			break loop
		case <-poll.C:
			stop, e := monitorDesiredState(ctx, a, c)
			if stop || monitorRevoked(e) {
				revoked = monitorRevoked(e)
				cancel()
				captureErr = <-done
				break loop
			}
		case <-retry.C:
			if e := deliverTrafficMonitor(ctx, a, q); monitorRevoked(e) {
				revoked = true
				cancel()
				captureErr = <-done
				break loop
			}
		case <-wake:
			if e := deliverTrafficMonitor(ctx, a, q); monitorRevoked(e) {
				revoked = true
				cancel()
				captureErr = <-done
				break loop
			}
		}
	}
	if revoked {
		return errors.Join(captureErr, stopRevokedTrafficMonitor(a, q))
	}
	status, detail := "STOPPED", "monitor stopped; pending metadata retained for retry"
	if captureErr != nil {
		status = "FAILED"
		detail = "monitor capture or durable queue failed"
	}
	if err = q.enqueue(status, nil, detail); err != nil {
		return errors.Join(captureErr, err)
	}
	finalCtx, finalCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer finalCancel()
	deliveryErr := deliverTrafficMonitor(finalCtx, a, q)
	if monitorRevoked(deliveryErr) {
		return errors.Join(captureErr, stopRevokedTrafficMonitor(a, q))
	}
	return errors.Join(captureErr, deliveryErr)
}
