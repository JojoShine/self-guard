package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

// Each redacted request is durably queued in its own file. Capacity is explicit;
// unacknowledged records are never evicted to make space for new requests.
type accessQueue struct {
	mu       sync.Mutex
	delivery sync.Mutex
	dir      string
	capacity int
	files    map[string]bool
}

func openAccessQueue(dir string, capacity int) (*accessQueue, error) {
	dir = filepath.Join(dir, "access-pending")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	q := &accessQueue{dir: dir, capacity: capacity, files: map[string]bool{}}
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".json") {
			q.files[entry.Name()] = true
		}
	}
	if len(q.files) > capacity {
		return nil, fmt.Errorf("access queue exceeds capacity")
	}
	return q, nil
}
func (q *accessQueue) count() int { q.mu.Lock(); defer q.mu.Unlock(); return len(q.files) }
func syncDirectory(dir string) error {
	f, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}
func (q *accessQueue) append(entry AccessEntry) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	digest := sha256.Sum256([]byte(entry.ID))
	name := fmt.Sprintf("%x.json", digest)
	if q.files[name] {
		return nil
	}
	if len(q.files) >= q.capacity {
		return fmt.Errorf("access queue full: new record rejected")
	}
	b, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	if err = persistConfig(filepath.Join(q.dir, name), b); err != nil {
		return err
	}
	q.files[name] = true
	return syncDirectory(q.dir)
}
func (q *accessQueue) deliver(client *http.Client, base, token, nodeID string) error {
	q.delivery.Lock()
	defer q.delivery.Unlock()
	q.mu.Lock()
	names := make([]string, 0, len(q.files))
	for name := range q.files {
		names = append(names, name)
	}
	q.mu.Unlock()
	sort.Strings(names)
	if len(names) > 100 {
		names = names[:100]
	}
	if len(names) == 0 {
		return nil
	}
	rows := []AccessEntry{}
	for _, name := range names {
		b, err := os.ReadFile(filepath.Join(q.dir, name))
		if err != nil {
			return err
		}
		var row AccessEntry
		if err = json.Unmarshal(b, &row); err != nil {
			return err
		}
		rows = append(rows, row)
	}
	b, err := json.Marshal(map[string]any{"nodeId": nodeID, "events": rows})
	if err != nil {
		return err
	}
	req, err := http.NewRequest("POST", base+"/api/telemetry/access", bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("access delivery status %d", resp.StatusCode)
	}
	// The API already durably acknowledged these immutable IDs. File deletion
	// and directory fsync must not serialize new audit appends behind a batch.
	removed := make([]string, 0, len(names))
	var removeErr error
	for _, name := range names {
		if err = os.Remove(filepath.Join(q.dir, name)); err != nil && !os.IsNotExist(err) {
			removeErr = err
			break
		}
		removed = append(removed, name)
	}
	q.mu.Lock()
	for _, name := range removed {
		delete(q.files, name)
	}
	q.mu.Unlock()
	return errors.Join(removeErr, syncDirectory(q.dir))
}
