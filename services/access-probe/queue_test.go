package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestQueueEncryptsRestartsAndAcknowledgesOnlyBoundEvent(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "queue")
	q, err := openQueue(dir, 8<<20)
	if err != nil {
		t.Fatal(err)
	}
	body := bytes.Repeat([]byte("synthetic-private-data"), 20000)
	e := q.newEvent()
	e.Operation = "GET"
	e.Route = "/orders"
	e.Result = "SUCCESS"
	n, err := e.response.Write(body)
	if err != nil || n != len(body) {
		t.Fatal("stream write", err)
	}
	e.ResponseBytes = int64(n)
	e.finish()
	if err = q.commit(e); err != nil {
		t.Fatal(err)
	}
	for _, file := range mustEntries(t, dir) {
		if !file.IsDir() {
			data, _ := os.ReadFile(filepath.Join(dir, file.Name()))
			if bytes.Contains(data, []byte("synthetic-private-data")) {
				t.Fatal("plaintext in queue")
			}
		}
	}
	q2, err := openQueue(dir, 8<<20)
	if err != nil {
		t.Fatal(err)
	}
	events, err := q2.pending()
	if err != nil || len(events) != 1 {
		t.Fatal("durability", err)
	}
	restored, err := q2.load(events[0])
	if err != nil || len(restored.Chunks) != 2 {
		t.Fatal("chunked event", err)
	}
	var got []byte
	for _, part := range restored.Chunks {
		data, err := q2.chunk(restored.EventID, part)
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, data...)
	}
	if !bytes.Equal(got, body) {
		t.Fatal("binary bytes not restored")
	}
	if err = q2.ack(events[0], "unrelated-event"); err == nil {
		t.Fatal("foreign acknowledgement removed evidence")
	}
	if err = q2.ack(events[0], restored.EventID); err != nil {
		t.Fatal(err)
	}
	if pending, _ := q2.pending(); len(pending) != 0 {
		t.Fatal("acknowledged event remained")
	}
}
func TestQueueFullAndTamperAreExplicitFailures(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "queue")
	q, err := openQueue(dir, 1024)
	if err != nil {
		t.Fatal(err)
	}
	e := q.newEvent()
	_, err = e.request.Write(bytes.Repeat([]byte("a"), 262144))
	if err == nil {
		t.Fatal("full queue silently accepted")
	}
	q, err = openQueue(filepath.Join(t.TempDir(), "queue"), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	e = q.newEvent()
	e.request.Write([]byte("abc"))
	e.RequestBytes = 3
	e.finish()
	if err = q.commit(e); err != nil {
		t.Fatal(err)
	}
	files, _ := q.pending()
	p := filepath.Join(q.root, files[0])
	raw, _ := os.ReadFile(p)
	raw[len(raw)-1] ^= 1
	os.WriteFile(p, raw, 0600)
	if _, err = q.load(files[0]); err == nil {
		t.Fatal("tampered event accepted")
	}
}
func mustEntries(t *testing.T, path string) []os.DirEntry {
	t.Helper()
	entries, err := os.ReadDir(path)
	if err != nil {
		t.Fatal(err)
	}
	return entries
}
func TestOfflineEvidenceExpiresByCaptureTimeWhileMetadataRemains(t *testing.T) {
	q, err := openQueue(filepath.Join(t.TempDir(), "queue"), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	e := q.newEvent()
	e.captureTime = func(string) time.Time { return time.Now().Add(-8 * 24 * time.Hour) }
	e.request.Write([]byte("old-business-bytes"))
	e.RequestBytes = 18
	e.finish()
	if err = q.commit(e); err != nil {
		t.Fatal(err)
	}
	if err = q.expire(time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err = q.chunk(e.EventID, e.Chunks[0]); err == nil {
		t.Fatal("offline body exceeded capture retention")
	}
	pending, _ := q.pending()
	if len(pending) != 1 {
		t.Fatal("expiry lost ordinary visit metadata")
	}
}

func TestQueueCanonicalizesCoverageSetsForStableReplay(t *testing.T) {
	q, err := openQueue(filepath.Join(t.TempDir(), "queue"), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	e := q.newEvent()
	e.Operation = "GET"
	e.gap("MIDSTREAM")
	e.gap("CAPTURE_LOSS")
	e.finish()
	if err = q.commit(e); err != nil {
		t.Fatal(err)
	}
	pending, err := q.pending()
	if err != nil || len(pending) != 1 {
		t.Fatal(err)
	}
	event, err := q.load(pending[0])
	if err != nil {
		t.Fatal(err)
	}
	if len(event.Gaps) != 2 || event.Gaps[0] != "CAPTURE_LOSS" {
		t.Fatal("unordered gap set can conflict on replay")
	}
}

func TestOversizeResponseFinishesADurablePartialInsteadOfStrandingChunks(t *testing.T) {
	q, err := openQueue(filepath.Join(t.TempDir(), "queue"), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	e := q.newEvent()
	e.Operation = "GET"
	n, writeErr := e.response.Write(bytes.Repeat([]byte("x"), 2<<20))
	if writeErr == nil {
		t.Fatal("fixture did not exhaust budget")
	}
	e.ResponseBytes = int64(n)
	e.finish()
	if err = q.commit(e); err != nil {
		t.Fatal("partial manifest missing after exhaustion", err)
	}
	pending, err := q.pending()
	if err != nil || len(pending) != 1 {
		t.Fatal("stranded chunks", err)
	}
	stored, err := q.load(pending[0])
	if err != nil || stored.Completeness != "PARTIAL" || len(stored.Chunks) == 0 {
		t.Fatal("partial evidence not preserved", err)
	}
}

func TestRestartReclaimsUncommittedBodiesWithADurableGapRecord(t *testing.T) {
	q, err := openQueue(filepath.Join(t.TempDir(), "queue"), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	e := q.newEvent()
	if _, err = e.response.Write(bytes.Repeat([]byte("x"), chunkBytes)); err != nil {
		t.Fatal(err)
	}
	count, err := q.recoverUncommitted()
	if err != nil || count != 1 {
		t.Fatal("crash recovery", count, err)
	}
	events, err := q.pending()
	if err != nil || len(events) != 1 {
		t.Fatal(err)
	}
	gap, err := q.load(events[0])
	if err != nil || gap.Operation != "PROBE_RECOVERY" || gap.Completeness != "PARTIAL" {
		t.Fatal("missing recovery gap", err)
	}
	if _, err = os.Stat(filepath.Join(q.root, chunkName(e.EventID, e.Chunks[0]))); !os.IsNotExist(err) {
		t.Fatal("uncommitted body still consumes queue")
	}
	if n, err := q.recoverUncommitted(); err != nil || n != 0 {
		t.Fatal("recovery replay", n, err)
	}
}

func TestLocalReplayCannotChangeChunkCaptureTime(t *testing.T) {
	q, err := openQueue(filepath.Join(t.TempDir(), "queue"), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	id := "00000000-0000-4000-8000-000000000003"
	at := time.Now()
	data := []byte("x")
	digest := sha256.Sum256(data)
	part := Chunk{Direction: "RESPONSE", Sequence: 0, CapturedAt: at.Format(time.RFC3339Nano), SHA256: hex.EncodeToString(digest[:]), Bytes: 1}
	if err = q.seal(chunkName(id, part), data, at); err != nil {
		t.Fatal(err)
	}
	if err = q.seal(chunkName(id, part), data, at.Add(time.Hour)); err == nil {
		t.Fatal("local replay silently extended capture time")
	}
	part.CapturedAt = at.Add(time.Hour).Format(time.RFC3339Nano)
	if _, err = q.chunk(id, part); err == nil {
		t.Fatal("manifest time not bound to encrypted capture time")
	}
}
