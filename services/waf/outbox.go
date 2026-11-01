package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"
)

// A single process owns this directory. Delivery never holds the mutex during network I/O.
type outbox struct {
	mu       sync.Mutex
	path     string
	items    []Event
	capacity int
}

func openOutbox(dir string, capacity int) (*outbox, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	q := &outbox{path: filepath.Join(dir, "events.json"), capacity: capacity}
	f, err := os.Open(q.path)
	if os.IsNotExist(err) {
		return q, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, (2<<20)+1))
	if err != nil {
		return nil, err
	}
	if len(b) > 2<<20 {
		return nil, fmt.Errorf("event outbox byte capacity exceeded")
	}
	if err = json.Unmarshal(b, &q.items); err != nil {
		return nil, err
	}
	if len(q.items) > capacity {
		return nil, fmt.Errorf("outbox exceeds capacity")
	}
	return q, nil
}
func (q *outbox) save(items []Event) error {
	b, err := json.Marshal(items)
	if err != nil {
		return err
	}
	if len(b) > 2<<20 {
		return fmt.Errorf("event outbox byte capacity exceeded")
	}
	if err = persistConfig(q.path, b); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(q.path))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
func (q *outbox) append(ev Event) error {
	raw, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	if len(raw)+16 > 128<<10 {
		return fmt.Errorf("event exceeds delivery wire budget")
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.items) >= q.capacity {
		return fmt.Errorf("outbox full")
	}
	next := append(append([]Event{}, q.items...), ev)
	if err := q.save(next); err != nil {
		return err
	}
	q.items = next
	return nil
}
func (q *outbox) deliver(client *http.Client, base, token string) error {
	q.mu.Lock()
	if len(q.items) == 0 {
		q.mu.Unlock()
		return nil
	}
	// Match the API's 100-event limit, with a separate wire-size budget.
	batch := []Event{}
	wireBytes := 16
	for _, event := range q.items {
		raw, err := json.Marshal(event)
		if err != nil {
			q.mu.Unlock()
			return err
		}
		if len(batch) >= 100 {
			break
		}
		if wireBytes+len(raw)+1 > 128<<10 {
			if len(batch) == 0 {
				q.mu.Unlock()
				return fmt.Errorf("retained event exceeds delivery wire budget")
			}
			break
		}
		batch = append(batch, event)
		wireBytes += len(raw) + 1
	}
	q.mu.Unlock()
	b, _ := json.Marshal(map[string]any{"events": batch})
	req, err := http.NewRequest("POST", base+"/api/waf/events", bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("event delivery status %d", resp.StatusCode)
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.items) < len(batch) {
		return nil
	}
	for i, event := range batch {
		if q.items[i].ID != event.ID {
			return nil
		}
	}
	next := append([]Event{}, q.items[len(batch):]...)
	if err = q.save(next); err != nil {
		return err
	}
	q.items = next
	return nil
}
