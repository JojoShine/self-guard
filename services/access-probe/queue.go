package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const chunkBytes = 262144

type Chunk struct {
	Direction  string `json:"direction"`
	Sequence   int    `json:"sequence"`
	CapturedAt string `json:"capturedAt"`
	SHA256     string `json:"sha256"`
	Bytes      int    `json:"bytes"`
}
type Queue struct {
	root  string
	key   []byte
	limit int64
	mu    sync.Mutex
}

func openQueue(root string, limit int64) (*Queue, error) {
	if limit < 1 {
		return nil, errors.New("queue budget required")
	}
	if err := os.MkdirAll(root, 0700); err != nil {
		return nil, err
	}
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("queue must be a private directory")
	}
	path := filepath.Join(root, "queue.key")
	key, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		key = make([]byte, 32)
		if _, err = rand.Read(key); err != nil {
			return nil, err
		}
		f, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if e != nil {
			return nil, e
		}
		_, err = f.Write(key)
		if err == nil {
			err = f.Sync()
		}
		ce := f.Close()
		if err != nil {
			return nil, err
		}
		if ce != nil {
			return nil, ce
		}
	} else if err != nil {
		return nil, err
	}
	info, err = os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || len(key) != 32 {
		return nil, errors.New("queue key unavailable")
	}
	return &Queue{root: root, key: key, limit: limit}, nil
}
func (q *Queue) usage() (int64, error) {
	entries, err := os.ReadDir(q.root)
	if err != nil {
		return 0, err
	}
	var total int64
	for _, e := range entries {
		if e.Type()&os.ModeSymlink != 0 {
			return 0, errors.New("symlink in evidence queue")
		}
		if !e.IsDir() {
			i, err := e.Info()
			if os.IsNotExist(err) {
				continue
			}
			if err != nil {
				return 0, err
			}
			total += i.Size()
		}
	}
	return total, nil
}
func (q *Queue) seal(name string, body []byte, captured ...time.Time) error {
	return q.sealReserved(name, body, false, captured...)
}
func (q *Queue) sealReserved(name string, body []byte, emergency bool, captured ...time.Time) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	if filepath.Base(name) != name || strings.Contains(name, "..") {
		return errors.New("invalid queue object")
	}
	if existing, readErr := q.unseal(name); readErr == nil {
		if strings.HasSuffix(name, ".chunk") && len(captured) > 0 {
			raw, err := os.ReadFile(filepath.Join(q.root, name))
			if err != nil || len(raw) < 8 || binary.BigEndian.Uint64(raw[:8]) != uint64(captured[0].UnixNano()) {
				return errors.New("queue capture identity conflict")
			}
		}
		if !bytes.Equal(existing, body) {
			return errors.New("queue object conflict")
		}
		return nil
	} else if !os.IsNotExist(readErr) {
		if _, statErr := os.Lstat(filepath.Join(q.root, name)); !os.IsNotExist(statErr) {
			return readErr
		}
	}
	block, err := aes.NewCipher(q.key)
	if err != nil {
		return err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return err
	}
	at := time.Now()
	if len(captured) > 0 {
		at = captured[0]
	}
	header := make([]byte, 8)
	binary.BigEndian.PutUint64(header, uint64(at.UnixNano()))
	aad := append([]byte(name), header...)
	data := append(header, aead.Seal(nonce, nonce, body, aad)...)
	used, err := q.usage()
	if err != nil {
		return err
	}
	ceiling := q.limit - min(q.limit/16, int64(65536))
	if strings.HasSuffix(name, ".chunk") {
		ceiling = q.limit - min(q.limit/8, int64(2<<20))
	}
	if emergency {
		ceiling = q.limit
	}
	if used+int64(len(data)) > ceiling {
		return errors.New("QUEUE_FULL")
	}
	tmp := filepath.Join(q.root, uuid()+".pending")
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err == nil {
		err = os.Link(tmp, filepath.Join(q.root, name))
	}
	removeErr := os.Remove(tmp)
	if err != nil {
		return err
	}
	if removeErr != nil {
		return removeErr
	}
	return syncDirectory(q.root)
}
func (q *Queue) unseal(name string) ([]byte, error) {
	if filepath.Base(name) != name || strings.Contains(name, "..") {
		return nil, errors.New("invalid queue object")
	}
	path := filepath.Join(q.root, name)
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > 2<<20 {
		return nil, errors.New("queue object invalid")
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(q.key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(body) < 8+aead.NonceSize() {
		return nil, errors.New("queue object truncated")
	}
	aadName := name
	if strings.HasSuffix(name, ".rejected") {
		if len(name) < 36 {
			return nil, errors.New("rejected record name invalid")
		}
		aadName = name[:36] + ".event"
	}
	aad := append([]byte(aadName), body[:8]...)
	return aead.Open(nil, body[8:8+aead.NonceSize()], body[8+aead.NonceSize():], aad)
}
func chunkName(eventID string, c Chunk) string {
	return fmt.Sprintf("%s-%s-%05d.chunk", eventID, c.Direction, c.Sequence)
}
func (q *Queue) newEvent() *Exchange {
	e := newExchange(nil, nil)
	e.request = &chunkWriter{queue: q, event: e, direction: "REQUEST"}
	e.response = &chunkWriter{queue: q, event: e, direction: "RESPONSE"}
	return e
}

type chunkWriter struct {
	queue      *Queue
	event      *Exchange
	direction  string
	sequence   int
	buffer     bytes.Buffer
	err        error
	capturedAt time.Time
}

func (w *chunkWriter) Write(b []byte) (int, error) {
	if w.err != nil {
		return 0, w.err
	}
	total := 0
	for len(b) > 0 {
		if w.buffer.Len() == 0 {
			w.capturedAt = time.Now()
			if w.event.captureTime != nil {
				if captured := w.event.captureTime(w.direction); !captured.IsZero() {
					w.capturedAt = captured
				}
			}
		}
		n := min(len(b), chunkBytes-w.buffer.Len())
		w.buffer.Write(b[:n])
		total += n
		b = b[n:]
		if w.buffer.Len() == chunkBytes {
			if err := w.flush(); err != nil {
				w.err = err
				return total, err
			}
		}
	}
	return total, nil
}
func (w *chunkWriter) flush() error {
	if w.buffer.Len() == 0 {
		return nil
	}
	if w.sequence > 65535 {
		return errors.New("RESOURCE_LIMIT")
	}
	body := w.buffer.Bytes()
	digest := sha256.Sum256(body)
	at := w.capturedAt
	part := Chunk{Direction: w.direction, Sequence: w.sequence, CapturedAt: at.UTC().Format(time.RFC3339Nano), SHA256: hex.EncodeToString(digest[:]), Bytes: len(body)}
	if err := w.queue.seal(chunkName(w.event.EventID, part), body, at); err != nil {
		return err
	}
	w.event.Chunks = append(w.event.Chunks, part)
	w.sequence++
	w.buffer.Reset()
	return nil
}
func (q *Queue) commit(e *Exchange) error {
	sort.Strings(e.Gaps)
	for _, writer := range []io.Writer{e.request, e.response} {
		w, ok := writer.(*chunkWriter)
		if !ok {
			return errors.New("evidence writer invalid")
		}
		err := w.err
		if err == nil {
			err = w.flush()
		}
		if err != nil {
			if err.Error() != "QUEUE_FULL" && err.Error() != "RESOURCE_LIMIT" {
				return err
			}
			e.gap(err.Error())
			w.buffer.Reset()
		}
	}
	if len(e.Chunks) > 8192 {
		return errors.New("RESOURCE_LIMIT")
	}
	sort.Strings(e.Gaps)
	body, err := json.Marshal(e)
	if err != nil {
		return err
	}
	err = q.seal(e.EventID+".event", body)
	if err == nil {
		return nil
	}
	if err.Error() != "QUEUE_FULL" {
		return err
	}
	e.gap("QUEUE_FULL")
	e.gap("BODY_NOT_CAPTURED")
	compact := *e
	compact.Operation = "CAPTURE_GAP"
	compact.Route = ""
	compact.Database = ""
	compact.DatabaseUser = ""
	compact.Objects = []Object{}
	compact.Fragments = nil
	compact.Chunks = []Chunk{}
	compact.Result = "UNKNOWN"
	compact.gap("QUEUE_FULL")
	compact.gap("BODY_NOT_CAPTURED")
	sort.Strings(compact.Gaps)
	metadata, err := json.Marshal(&compact)
	if err != nil {
		return err
	}
	if err = q.sealReserved(e.EventID+".event", metadata, true); err != nil {
		return err
	}
	for _, part := range e.Chunks {
		if err = os.Remove(filepath.Join(q.root, chunkName(e.EventID, part))); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return syncDirectory(q.root)
}

func (q *Queue) pending() ([]string, error) {
	entries, err := os.ReadDir(q.root)
	if err != nil {
		return nil, err
	}
	var files []string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".event") {
			files = append(files, e.Name())
		}
	}
	sort.Strings(files)
	return files, nil
}
func (q *Queue) load(name string) (*Exchange, error) {
	body, err := q.unseal(name)
	if err != nil {
		return nil, err
	}
	var e Exchange
	if err = json.Unmarshal(body, &e); err != nil {
		return nil, err
	}
	if name != e.EventID+".event" && !(strings.HasSuffix(name, ".rejected") && strings.HasPrefix(name, e.EventID+"-")) {
		return nil, errors.New("event binding mismatch")
	}
	return &e, nil
}
func (q *Queue) chunk(eventID string, c Chunk) ([]byte, error) {
	body, err := q.unseal(chunkName(eventID, c))
	if err != nil {
		return nil, err
	}
	at, err := time.Parse(time.RFC3339Nano, c.CapturedAt)
	if err != nil {
		return nil, errors.New("chunk capture timestamp invalid")
	}
	raw, err := os.ReadFile(filepath.Join(q.root, chunkName(eventID, c)))
	if err != nil || len(raw) < 8 || binary.BigEndian.Uint64(raw[:8]) != uint64(at.UnixNano()) {
		return nil, errors.New("chunk capture timestamp mismatch")
	}
	digest := sha256.Sum256(body)
	if len(body) != c.Bytes || hex.EncodeToString(digest[:]) != c.SHA256 {
		return nil, errors.New("chunk checksum mismatch")
	}
	return body, nil
}
func (q *Queue) ack(name, eventID string) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	e, err := q.load(name)
	if err != nil {
		return err
	}
	if e.EventID != eventID {
		return errors.New("acknowledgement not bound to event")
	}
	for _, c := range e.Chunks {
		if err = os.Remove(filepath.Join(q.root, chunkName(e.EventID, c))); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	if err = os.Remove(filepath.Join(q.root, name)); err != nil {
		return err
	}
	return syncDirectory(q.root)
}
func syncDirectory(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

func (q *Queue) expire(now time.Time) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	files, err := os.ReadDir(q.root)
	if err != nil {
		return err
	}
	for _, file := range files {
		if !strings.HasSuffix(file.Name(), ".chunk") && !strings.HasSuffix(file.Name(), ".pending") && !strings.HasSuffix(file.Name(), ".rejected") {
			continue
		}
		path := filepath.Join(q.root, file.Name())
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return errors.New("invalid queue file")
		}
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		var header [8]byte
		_, readErr := io.ReadFull(f, header[:])
		f.Close()
		if readErr != nil {
			if info.ModTime().Before(now.Add(-time.Hour)) {
				if err = os.Remove(path); err != nil {
					return err
				}
			}
			continue
		}
		at := time.Unix(0, int64(binary.BigEndian.Uint64(header[:])))
		if at.After(now.Add(5*time.Minute)) || !now.Before(at.Add(7*24*time.Hour)) {
			if err = os.Remove(path); err != nil {
				return err
			}
		}
	}
	return syncDirectory(q.root)
}
