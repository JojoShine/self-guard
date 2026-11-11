package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"
	"unicode/utf16"
)

func TestSanitize(t *testing.T) {
	raw := []byte(`{"timestamp":"2026-11-06T10:00:00.123456+0800","event_type":"http","flow_id":18446744073709551615,"http":{"url":"https://user:password@example.com/path?secret=value#fragment","http_method":"GET","cookie":"secret-cookie","headers":{"Authorization":"secret-auth"}},"payload":"secret-payload"}`)
	e, err := normalize(raw, "generation", 0)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(e)
	s := string(b)
	for _, bad := range []string{"secret", "password", "payload", "cookie", "headers", "user:"} {
		if strings.Contains(s, bad) {
			t.Fatalf("leaked %s", bad)
		}
	}
	if e.FlowID != "18446744073709551615" || e.Metadata["http"].(map[string]any)["path"] != "/path" {
		t.Fatal(s)
	}
	e2, _ := normalize(raw, "generation", 0)
	if e.EventID != e2.EventID {
		t.Fatal("unstable id")
	}
}
func TestUnknownSkipped(t *testing.T) {
	_, err := normalize([]byte(`{"event_type":"fileinfo"}`), "a", 0)
	if err != errSkipped {
		t.Fatal(err)
	}
}
func TestCounters(t *testing.T) {
	e, err := normalize([]byte(`{"timestamp":"2026-11-06T00:00:00Z","event_type":"stats","stats":{"capture":{"kernel_packets":18446744073709551615},"detect":{"engines":[{"rules_loaded":12,"rules_failed":2},{"rules_loaded":8,"rules_skipped":1}]}}}`), "a", 0)
	if err != nil {
		t.Fatal(err)
	}
	s := e.Metadata["stats"].(map[string]any)
	if s["kernelPackets"] != "18446744073709551615" || s["rulesLoaded"] != int64(20) {
		t.Fatal(s)
	}
}
func TestPartialRotationAndLongline(t *testing.T) {
	dir := t.TempDir()
	p := dir + "/eve.json"
	os.WriteFile(p, []byte(`{"timestamp":"2026-11-06T00:00:00Z","event_type":"http","http":{"url":"/a"}}`), 0600)
	r := reader{path: p}
	c := Cursor{}
	events, next, h, err := r.read(c, true)
	if err != nil || len(events) != 0 || next.Offset != 0 {
		t.Fatal(events, next, h, err)
	}
	f, _ := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0600)
	f.WriteString("\n")
	f.Close()
	events, next, _, err = r.read(next, true)
	if err != nil || len(events) != 1 {
		t.Fatal(events, err)
	}
	old := events[0].EventID
	os.Rename(p, p+".1")
	os.WriteFile(p, []byte(strings.Repeat("x", maxLine+20)+"\n"+`{"timestamp":"2026-11-06T00:00:01Z","event_type":"flow","flow":{}}`+"\n"), 0600)
	events, next, h, err = r.read(next, true)
	if len(events) == 0 && err == nil {
		events, next, h, err = r.read(next, true)
	}
	if err != nil || len(events) != 1 || h.InvalidLines != 1 || old == events[0].EventID {
		t.Fatal(events, next, h, err)
	}
	r.close()
}
func TestWrongAckRetainsPending(t *testing.T) {
	dir := t.TempDir()
	calls := 0
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		fmt.Fprint(w, `{"sensorId":"s","batchId":"wrong","persisted":true,"accepted":1}`)
	}))
	defer s.Close()
	client, err := newClient(Config{Server: s.URL, SensorID: "s", Token: "private"}, true)
	if err != nil {
		t.Fatal(err)
	}
	st := State{Pending: &Pending{Batch: Batch{BatchID: "batch", Events: []Event{{EventID: "id"}}}, Next: Cursor{Offset: 10}}}
	if err := deliver(client, dir, &st); err == nil || st.Cursor.Offset != 0 || st.Pending == nil || calls != 1 {
		t.Fatal(st, err, calls)
	}
}
func TestPendingRetryStable(t *testing.T) {
	dir := t.TempDir()
	var ids []string
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var b Batch
		json.NewDecoder(r.Body).Decode(&b)
		ids = append(ids, b.BatchID)
		if len(ids) == 1 {
			w.WriteHeader(503)
			return
		}
		fmt.Fprintf(w, `{"sensorId":"s","batchId":%q,"persisted":true,"accepted":0}`, b.BatchID)
	}))
	defer s.Close()
	client, _ := newClient(Config{Server: s.URL, SensorID: "s"}, true)
	st := State{Pending: &Pending{Batch: Batch{BatchID: "fixed", Events: []Event{}}, Next: Cursor{Offset: 17}}}
	if err := saveState(dir, st); err != nil {
		t.Fatal(err)
	}
	if deliver(client, dir, &st) == nil {
		t.Fatal("expected offline")
	}
	st2, err := loadState(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err = deliver(client, dir, &st2); err != nil || st2.Pending != nil || st2.Cursor.Offset != 17 || strings.Join(ids, ",") != "fixed,fixed" {
		t.Fatal(st2, err, ids)
	}
}
func TestDisabledStopsBeforeRead(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"sensorId":"s","assetId":"a","enabled":false,"version":1}`)
	}))
	defer s.Close()
	c, _ := newClient(Config{Server: s.URL, SensorID: "s", AssetID: "a"}, true)
	if c.check() == nil {
		t.Fatal("disabled allowed")
	}
}

func TestStartAtEndAndRestart(t *testing.T) {
	dir := t.TempDir()
	p := dir + "/eve.json"
	line := `{"timestamp":"2026-11-06T00:00:00Z","event_type":"flow","flow":{"bytes_toserver":18446744073709551615}}` + "\n"
	os.WriteFile(p, []byte(line), 0600)
	r := reader{path: p}
	events, c, _, err := r.read(Cursor{}, false)
	if err != nil || len(events) != 0 || c.Offset != int64(len(line)) {
		t.Fatal(events, c, err)
	}
	f, _ := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0600)
	f.WriteString(line)
	f.Close()
	events, c, _, err = r.read(c, false)
	if err != nil || len(events) != 1 {
		t.Fatal(events, c, err)
	}
	id := events[0].EventID
	r.close()
	r2 := reader{path: p}
	defer r2.close()
	events, _, _, err = r2.read(c, false)
	if err != nil || len(events) != 0 {
		t.Fatal("replayed committed event", id, events, err)
	}
}
func TestLostRotationAndTruncation(t *testing.T) {
	dir := t.TempDir()
	p := dir + "/eve.json"
	line := `{"timestamp":"2026-11-06T00:00:00Z","event_type":"flow","flow":{}}` + "\n"
	os.WriteFile(p, []byte(line), 0600)
	r := reader{path: p}
	_, c, _, _ := r.read(Cursor{}, true)
	r.close()
	os.Rename(p, p+".gone")
	os.WriteFile(p, []byte(line), 0600)
	os.Remove(p + ".gone")
	events, c, h, err := r.read(c, true)
	if err != nil || len(events) != 1 || h.RotationGaps != 1 {
		t.Fatal(events, c, h, err)
	}
	os.WriteFile(p, []byte("{\n"), 0600)
	_, _, h, err = r.read(c, true)
	if err != nil || h.RotationGaps != 1 || h.InvalidLines != 1 {
		t.Fatal(h, err)
	}
	r.close()
}
func TestWriterLockAndPrivateState(t *testing.T) {
	dir := t.TempDir()
	unlock, err := lockState(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	if u, e := lockState(dir); e == nil {
		u()
		t.Fatal("second writer allowed")
	}
	if err = saveState(dir, State{}); err != nil {
		t.Fatal(err)
	}
	s, _ := os.Stat(dir + "/state.json")
	if s.Mode().Perm() != 0600 {
		t.Fatal(s.Mode())
	}
}
func TestLoopbackOnlyHTTP(t *testing.T) {
	for _, s := range []string{"http://example.com", "http://localhost", "http://10.0.0.1", "https://user:password@example.com"} {
		if _, err := newClient(Config{Server: s}, true); err == nil {
			t.Fatal(s)
		}
	}
	if _, err := newClient(Config{Server: "http://127.0.0.1"}, false); err == nil {
		t.Fatal("HTTP opt-in required")
	}
}

func TestStartAtEndSkipsExistingPartialLine(t *testing.T) {
	dir := t.TempDir()
	p := dir + "/eve.json"
	os.WriteFile(p, []byte("old partial"), 0600)
	r := reader{path: p}
	defer r.close()
	_, c, _, _ := r.read(Cursor{}, false)
	f, _ := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0600)
	f.WriteString(`{"timestamp":"2026-11-06T00:00:00Z","event_type":"flow","flow":{}}` + "\n")
	f.Close()
	events, _, _, err := r.read(c, false)
	if err != nil || len(events) != 0 {
		t.Fatal("uploaded continuation of existing line", events, err)
	}
}
func TestRecoverRotationSiblingAfterRestart(t *testing.T) {
	dir := t.TempDir()
	p := dir + "/eve.json"
	line := `{"timestamp":"2026-11-06T00:00:00Z","event_type":"flow","flow":{}}` + "\n"
	os.WriteFile(p, []byte(line), 0600)
	r := reader{path: p}
	_, c, _, _ := r.read(Cursor{}, true)
	f, _ := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0600)
	f.WriteString(line)
	f.Close()
	r.close()
	os.Rename(p, p+".1")
	os.WriteFile(p, []byte(line), 0600)
	r = reader{path: p}
	defer r.close()
	events, next, h, err := r.read(c, true)
	if err != nil || len(events) != 1 || h.RotationGaps != 1 {
		t.Fatal(events, next, h, err)
	}
	events, _, h, err = r.read(next, true)
	if err != nil || len(events) != 1 || h.RotationGaps != 0 {
		t.Fatal(events, h, err)
	}
}
func TestFIFORejectedWithoutBlocking(t *testing.T) {
	p := t.TempDir() + "/fifo"
	if err := syscall.Mkfifo(p, 0600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		f, e := regularOpen(p)
		if f != nil {
			f.Close()
		}
		done <- e
	}()
	select {
	case e := <-done:
		if e == nil {
			t.Fatal("FIFO accepted")
		}
	case <-time.After(time.Second):
		t.Fatal("FIFO open blocked")
	}
}

func TestDeniedBatchesNeverDiscardPending(t *testing.T) {
	for _, status := range []int{400, 401, 403} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			dir := t.TempDir()
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(status) }))
			defer s.Close()
			c, _ := newClient(Config{Server: s.URL, SensorID: "s"}, true)
			st := State{Cursor: Cursor{Offset: 3}, Pending: &Pending{Batch: Batch{BatchID: "fixed", Events: []Event{}}, Next: Cursor{Offset: 19}}}
			saveState(dir, st)
			if deliver(c, dir, &st) == nil {
				t.Fatal("denial accepted")
			}
			disk, e := loadState(dir)
			if e != nil || st.Pending == nil || disk.Pending == nil || st.Cursor.Offset != 3 || disk.Cursor.Offset != 3 {
				t.Fatal(st, disk, e)
			}
		})
	}
}
func TestSanitizedPendingHasNoRawFields(t *testing.T) {
	raw := []byte(`{"timestamp":"2026-11-06T00:00:00Z","event_type":"http","http":{"url":"https://secret-user:secret-pass@example.com/path?secret-token=value#secret-fragment","http_method":"GET","http_user_agent":"secret-agent","request_headers":{"Cookie":"secret-cookie"}},"packet":"secret-packet","payload":"secret-payload"}`)
	e, err := normalize(raw, "a", 0)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err = saveState(dir, State{Pending: &Pending{Batch: Batch{Events: []Event{e}}}}); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(dir + "/state.json")
	if strings.Contains(string(b), "secret") || strings.Contains(string(b), "payload") || strings.Contains(string(b), "packet") {
		t.Fatal("sensitive data persisted")
	}
}

func TestStringCapsMatchWireUTF16Length(t *testing.T) {
	s := str(strings.Repeat("😀", 40), 32)
	if len(utf16.Encode([]rune(s))) > 32 {
		t.Fatal("wire limit exceeded")
	}
}

func TestLonglineWithoutNewlineCountsOnce(t *testing.T) {
	p := t.TempDir() + "/eve.json"
	os.WriteFile(p, []byte(strings.Repeat("x", maxLine+1)), 0600)
	r := reader{path: p}
	defer r.close()
	_, c, h, err := r.read(Cursor{}, true)
	if err != nil || h.InvalidLines != 1 || !c.Discard {
		t.Fatal(c, h, err)
	}
	f, _ := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0600)
	f.WriteString("\n")
	f.Close()
	_, _, h, err = r.read(c, true)
	if err != nil || h.InvalidLines != 0 {
		t.Fatal(h, err)
	}
}

func TestRuleFileFingerprintAndBound(t *testing.T) {
	p := t.TempDir() + "/rules"
	os.WriteFile(p, []byte("approved rules\n"), 0600)
	h := Health{Status: "READING", DetailCode: "OK"}
	rulesHealth(Config{RuleFile: p}, &h)
	if h.RulesSHA256 != digest([]byte("approved rules\n")) || h.RulesModifiedAt == "" {
		t.Fatal(h)
	}
	h = Health{}
	rulesHealth(Config{RuleFile: p, ExpectedRuleSHA256: strings.Repeat("0", 64)}, &h)
	if h.Status != "ERROR" || h.DetailCode != "RULE_FILE_UNAVAILABLE" {
		t.Fatal(h)
	}
	os.Truncate(p, 32*1024*1024+1)
	h = Health{}
	rulesHealth(Config{RuleFile: p}, &h)
	if h.Status != "ERROR" || h.RulesSHA256 != "" {
		t.Fatal(h)
	}
}

func TestOnceRequiresCompleteReadableEOF(t *testing.T) {
	for _, kind := range []string{"missing", "directory", "partial", "oversized-partial", "complete"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			identity := dir + "/identity.json"
			os.WriteFile(identity, []byte(`{"assetId":"a","token":"must-never-use"}`), 0600)
			eve := dir + "/eve.json"
			switch kind {
			case "directory":
				os.Mkdir(eve, 0700)
			case "partial":
				os.WriteFile(eve, []byte(`{"timestamp":"2026-11-06T00:00:00Z","event_type":"flow","flow":{}}`), 0600)
			case "oversized-partial":
				os.WriteFile(eve, []byte(strings.Repeat("x", maxLine+1)), 0600)
			case "complete":
				os.WriteFile(eve, []byte(`{"timestamp":"2026-11-06T00:00:00Z","event_type":"flow","flow":{}}`+"\n"), 0600)
			}
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == "GET" {
					fmt.Fprint(w, `{"sensorId":"s","assetId":"a","enabled":true,"version":1}`)
					return
				}
				var b Batch
				if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
					t.Error(err)
					w.WriteHeader(400)
					return
				}
				fmt.Fprintf(w, `{"sensorId":"s","batchId":%q,"persisted":true,"accepted":%d}`, b.BatchID, len(b.Events))
			}))
			defer s.Close()
			err := run(Config{Server: s.URL, SensorID: "s", AssetID: "a", IdentityPath: identity, EVEPath: eve, StateDir: dir + "/state"}, true, true)
			if kind == "complete" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil {
				t.Fatal("incomplete replay reported success")
			}
		})
	}
}
func TestMultipleRotationsCannotSilentlySkipRetainedSibling(t *testing.T) {
	dir := t.TempDir()
	p := dir + "/eve.json"
	line := func(path string) []byte {
		return []byte(fmt.Sprintf(`{"timestamp":"2026-11-06T00:00:00Z","event_type":"http","http":{"url":%q}}`+"\n", path))
	}
	os.WriteFile(p, line("/A"), 0600)
	r := reader{path: p}
	defer r.close()
	_, c, _, _ := r.read(Cursor{}, true)
	os.Rename(p, p+".2")
	os.WriteFile(p, line("/B"), 0600)
	os.Rename(p, p+".1")
	os.WriteFile(p, line("/C"), 0600)
	var paths []string
	var gaps uint64
	for i := 0; i < 4; i++ {
		events, next, h, err := r.read(c, true)
		if err != nil {
			t.Fatal(err)
		}
		gaps += h.RotationGaps
		for _, e := range events {
			paths = append(paths, e.Metadata["http"].(map[string]any)["path"].(string))
		}
		c = next
	}
	if strings.Join(paths, ",") != "/B,/C" && gaps == 0 {
		t.Fatalf("skipped retained sibling without gap: %v", paths)
	}
}
func TestOutOfWireRangeUTCTimestampBecomesInvalidLine(t *testing.T) {
	raw := []byte(`{"timestamp":"9999-12-31T23:59:59-12:00","event_type":"flow","flow":{}}`)
	if _, err := normalize(raw, "g", 0); err == nil {
		t.Fatal("UTC year 10000 accepted")
	}
	p := t.TempDir() + "/eve.json"
	os.WriteFile(p, append(raw, '\n'), 0600)
	r := reader{path: p}
	defer r.close()
	events, _, h, err := r.read(Cursor{}, true)
	if err != nil || len(events) != 0 || h.InvalidLines != 1 {
		t.Fatal(events, h, err)
	}
}

func TestReaderIdleEOFRemainsReading(t *testing.T) {
	p := t.TempDir() + "/eve.json"
	if err := os.WriteFile(p, nil, 0600); err != nil {
		t.Fatal(err)
	}
	r := reader{path: p}
	defer r.close()
	var c Cursor
	for i := 0; i < 3; i++ {
		events, next, h, err := r.read(c, false)
		if err != nil || len(events) != 0 || h.Status != "READING" || h.DetailCode != "OK" {
			t.Fatalf("idle readable EVE: %+v %v", h, err)
		}
		c = next
	}
	if err := os.WriteFile(p, []byte(`{"timestamp":"2026-11-06T00:00:00Z","event_type":"flow","flow":{}}`+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		events, next, h, err := r.read(c, false)
		if err != nil || len(events) != 1-i || h.Status != "READING" || h.DetailCode != "OK" {
			t.Fatalf("event then idle EVE: %+v events=%d %v", h, len(events), err)
		}
		c = next
	}
	if err := r.f.Close(); err != nil {
		t.Fatal(err)
	}
	_, _, h, err := r.read(c, false)
	if err == nil || h.Status != "ERROR" || h.DetailCode != "READ_ERROR" {
		t.Fatalf("closed handle: %+v %v", h, err)
	}
}
func TestReaderMissingAndInvalidFileHealth(t *testing.T) {
	p := t.TempDir() + "/eve.json"
	r := reader{path: p}
	defer r.close()
	_, _, h, err := r.read(Cursor{}, false)
	if err == nil || h.Status != "WAITING" || h.DetailCode != "WAITING_FOR_EVE" {
		t.Fatalf("missing: %+v %v", h, err)
	}
	if err := os.Mkdir(p, 0700); err != nil {
		t.Fatal(err)
	}
	_, _, h, err = r.read(Cursor{}, false)
	if err == nil || h.Status != "ERROR" || h.DetailCode != "READ_ERROR" {
		t.Fatalf("nonregular: %+v %v", h, err)
	}
}
