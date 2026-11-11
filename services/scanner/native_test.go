package scanner

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"
)

func TestNativeRejectsUnsafeTemplateBeforeProcess(t *testing.T) {
	for _, raw := range []string{`{"id":"test","info":{"name":"test","author":"selfguard","severity":"info"},"http":[{"method":"GET","path":["{{BaseURL}}"],"matchers":[{"type":"dsl","dsl":["http_get('http://localhost')"]}]}]}`, `{"flow":"http(1)"}`} {
		rule := HTTPRule{ID: "test", Description: "test", Operator: "ALL", MaxRedirects: new(int), NativeTemplate: &NativeTemplate{Raw: raw, SHA256: hashBytes([]byte(raw)), EngineVersion: "3.11.1"}}
		if _, err := validateHTTPRule(rule, "GET"); err == nil {
			t.Fatal("unsafe native rule accepted")
		}
	}
}
func TestNativeSampleUsesActualEngine(t *testing.T) {
	if testing.Short() || os.Getenv("NUCLEI_BINARY") == "" {
		t.Skip("native binary integration")
	}
	raw := `{"id":"owned-native","info":{"name":"owned","author":"selfguard","severity":"info"},"http":[{"method":"GET","path":["{{BaseURL}}"],"matchers":[{"type":"dsl","dsl":["status_code == 200 && contains(body, 'owned')"]}]}]}`
	rule := HTTPRule{ID: "owned-native", Description: "owned", Operator: "ALL", MaxRedirects: new(int), NativeTemplate: &NativeTemplate{Raw: raw, SHA256: hashBytes([]byte(raw)), EngineVersion: "3.11.1"}}
	for _, body := range []string{"owned", "absent"} {
		result, err := CheckRule("GET", rule, RuleSample{Status: 200, Body: body})
		if err != nil {
			t.Fatal(err)
		}
		if result.Matched != (body == "owned") || result.Native == nil || result.Native.EngineVersion != "3.11.1" {
			data, _ := json.Marshal(result)
			t.Fatalf("wrong native evaluation: %s", data)
		}
	}
}

func TestNativeCompilationAndUnsafeFunctions(t *testing.T) {
	for _, expr := range []string{"http_get(body)", "contains(raw, 'owned')", "contains(header, 'owned')", "contains(gzip_decode(body), 'x')", "contains(replace(body, 'x', body), 'x')", "body_1 == body", "contains(host, 'x')", "contains(body, '{{interactsh-url}}')"} {
		if nativeDSLAllowed(expr) {
			t.Fatalf("unsafe expression accepted: %s", expr)
		}
	}
	if testing.Short() || os.Getenv("NUCLEI_BINARY") == "" {
		return
	}
	raw := `{"id":"compile-owned","info":{"name":"owned","author":"selfguard","severity":"info"},"http":[{"method":"GET","path":["{{BaseURL}}"],"matchers":[{"type":"status","status":[200]}]}]}`
	rule := HTTPRule{ID: "compile-owned", Description: "owned", Operator: "ALL", MaxRedirects: new(int), NativeTemplate: &NativeTemplate{Raw: raw, SHA256: hashBytes([]byte(raw)), EngineVersion: "3.11.1"}}
	proof, err := CompileNativeRule("GET", rule)
	if err != nil || !proof.Passed || len(proof.Samples) != 0 || proof.ValidationKind != "NATIVE_TEMPLATE_COMPILE" {
		t.Fatalf("compile failed: %+v %v", proof, err)
	}
}

func TestNativeResponseFramingFailsClosedAndCleansPrivateFiles(t *testing.T) {
	if testing.Short() || os.Getenv("NUCLEI_BINARY") == "" {
		t.Skip("requires actual pinned native binary")
	}
	temp := t.TempDir()
	t.Setenv("TMPDIR", temp)
	raw := `{"id":"framing-owned","info":{"name":"owned","author":"selfguard","severity":"info"},"http":[{"method":"GET","path":["{{BaseURL}}"],"matchers":[{"type":"status","status":[200]}]}]}`
	rule := HTTPRule{ID: "framing-owned", Description: "owned", Operator: "ALL", MaxRedirects: new(int), NativeTemplate: &NativeTemplate{Raw: raw, SHA256: hashBytes([]byte(raw)), EngineVersion: "3.11.1"}}
	_, err := CheckRule("GET", rule, RuleSample{Status: 200, Headers: map[string][]string{"Content-Length": {"100"}}})
	if err == nil {
		t.Fatal("unrepresentable response became a native negative result")
	}
	entries, err := os.ReadDir(temp)
	if err != nil || len(entries) != 0 {
		t.Fatalf("private response files remain: %v %v", entries, err)
	}
}

func TestNativeActualChunkedResponseKeepsFramingAndBodySemantics(t *testing.T) {
	if testing.Short() || os.Getenv("NUCLEI_BINARY") == "" {
		t.Skip("requires actual pinned native binary")
	}
	for _, body := range []string{"owned", "absent"} {
		engine, _, budget := httpFixture(t, func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Accept-Encoding") != "identity" {
				t.Error("native transport did not request identity")
			}
			w.Header().Set("Content-Type", "text/plain")
			w.(http.Flusher).Flush()
			w.Write([]byte(body))
		})
		raw := `{"id":"chunked-owned","info":{"name":"owned","author":"selfguard","severity":"info"},"http":[{"method":"GET","path":["{{BaseURL}}"],"matchers":[{"type":"dsl","dsl":["contains(response, 'Transfer-Encoding: chunked') && contains(body, 'owned')"]}]}]}`
		rule := HTTPRule{ID: "chunked-owned", Description: "owned", Operator: "ALL", MaxRedirects: new(int), NativeTemplate: &NativeTemplate{Raw: raw, SHA256: hashBytes([]byte(raw)), EngineVersion: "3.11.1"}}
		result := engine.HTTP(context.Background(), "GET", "/public", rule)
		expected := "NOT_FOUND"
		if body == "owned" {
			expected = "CONFIRMED"
		}
		if result.Outcome != expected || result.Evidence.Native == nil || budget.calls.Load() != 1 {
			t.Fatalf("chunk framing/response semantics lost: %+v", result)
		}
	}
}
func TestNativeActualUnexpectedCompressionIsInconclusive(t *testing.T) {
	if testing.Short() || os.Getenv("NUCLEI_BINARY") == "" {
		t.Skip("requires actual pinned native binary")
	}
	engine, _, _ := httpFixture(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Accept-Encoding") != "identity" {
			t.Error("native transport did not request identity")
		}
		w.Header().Set("Content-Encoding", "gzip")
		writer := gzip.NewWriter(w)
		writer.Write([]byte("owned"))
		writer.Close()
	})
	raw := `{"id":"gzip-owned","info":{"name":"owned","author":"selfguard","severity":"info"},"http":[{"method":"GET","path":["{{BaseURL}}"],"matchers":[{"type":"word","words":["owned"]}]}]}`
	rule := HTTPRule{ID: "gzip-owned", Description: "owned", Operator: "ALL", MaxRedirects: new(int), NativeTemplate: &NativeTemplate{Raw: raw, SHA256: hashBytes([]byte(raw)), EngineVersion: "3.11.1"}}
	result := engine.HTTP(context.Background(), "GET", "/public", rule)
	if result.Outcome != "INCONCLUSIVE" || result.Evidence.Native != nil {
		t.Fatalf("unexpected compression approximated: %+v", result)
	}
}

func TestNativeHeadRetainsContentLengthWithoutInventingBody(t *testing.T) {
	if testing.Short() || os.Getenv("NUCLEI_BINARY") == "" {
		t.Skip("requires actual pinned native binary")
	}
	raw := `{"id":"head-owned","info":{"name":"owned","author":"selfguard","severity":"info"},"http":[{"method":"HEAD","path":["{{BaseURL}}"],"matchers":[{"type":"dsl","dsl":["status_code == 200 && content_length == 100 && len(body) == 0 && contains(response, 'Content-Length: 100')"]}]}]}`
	rule := HTTPRule{ID: "head-owned", Description: "owned", Operator: "ALL", MaxRedirects: new(int), NativeTemplate: &NativeTemplate{Raw: raw, SHA256: hashBytes([]byte(raw)), EngineVersion: "3.11.1"}}
	result, err := CheckRule("HEAD", rule, RuleSample{Status: 200, Headers: http.Header{"Content-Length": {"100"}}})
	if err != nil || !result.Matched {
		t.Fatalf("HEAD response semantics changed: %+v %v", result, err)
	}
}

func TestNativeIntrusivePathsNeverConsumeTargetAllowance(t *testing.T) {
	engine, dial, budget := httpFixture(t, func(w http.ResponseWriter, r *http.Request) { t.Error("intrusive path requested") })
	raw := `{"id":"safe-status","info":{"name":"owned","author":"selfguard","severity":"info","tags":["cve"]},"http":[{"method":"GET","path":["{{BaseURL}}"],"matchers":[{"type":"status","status":[200]}]}]}`
	rule := HTTPRule{ID: "safe-status", Description: "owned", Operator: "ALL", MaxRedirects: new(int), NativeTemplate: &NativeTemplate{Raw: raw, SHA256: hashBytes([]byte(raw)), EngineVersion: "3.11.1"}}
	for _, path := range []string{"/public/;cat$IFS/etc/passwd", "/public/shutdown", "/public/logout", "/public/reboot", "/public/reset"} {
		result := engine.HTTP(context.Background(), "GET", path, rule)
		if result.Outcome != "INCONCLUSIVE" || result.Reason != "NATIVE_INTRUSIVE_PATH_UNSUPPORTED" {
			t.Fatalf("intrusive path accepted: %+v", result)
		}
	}
	if dial.calls.Load() != 0 || budget.calls.Load() != 0 {
		t.Fatal("intrusive path consumed allowance")
	}
	rule.NativeTemplate.Raw = strings.Replace(raw, `"cve"`, `"rce"`, 1)
	rule.NativeTemplate.SHA256 = hashBytes([]byte(rule.NativeTemplate.Raw))
	if _, err := validateHTTPRule(rule, "GET"); err == nil {
		t.Fatal("intrusive native category accepted")
	}
}
