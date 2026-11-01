package main

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

type secWireCorpusCase struct {
	File             string `json:"file"`
	FileSHA256       string `json:"fileSha256"`
	RuleID           string `json:"ruleId"`
	TestID           int    `json:"testId"`
	Stage            int    `json:"stage"`
	RequestBase64    string `json:"requestBase64"`
	ExpectedStatuses []int  `json:"expectedStatuses"`
	Threshold        int    `json:"threshold"`
}

// This checks actual HTTP responses separately from the existing worker rule-ID
// corpus. A server-level rejection must not be relabeled as a matched CRS rule.
func TestSecFrozenCorpusActualHTTPStatuses(t *testing.T) {
	inputPath, binary, outputPath := os.Getenv("WAF_CORPUS_HTTP_INPUT"), os.Getenv("WAF_CORPUS_HTTP_BINARY"), os.Getenv("WAF_CORPUS_HTTP_OUTPUT")
	if inputPath == "" || binary == "" || outputPath == "" {
		t.Skip("requires the controlled frozen HTTP-status corpus and explicit worker binary")
	}
	var input struct {
		ArchiveSHA256 string              `json:"archiveSha256"`
		Files         []secLangFile       `json:"files"`
		Cases         []secWireCorpusCase `json:"cases"`
	}
	raw, err := os.ReadFile(inputPath)
	if err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&input); err != nil {
		t.Fatal(err)
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		t.Fatal("extra corpus content")
	}
	if input.ArchiveSHA256 != "0539e66e7627fe71c160a644d8fb7ab6e450d53c9de208be5f95a35c70e1a154" || len(input.Cases) == 0 || len(input.Cases) > 100 {
		t.Fatal("frozen corpus identity or bounded status selection is invalid")
	}
	program, err := os.ReadFile(binary)
	if err != nil {
		t.Fatal(err)
	}
	programSHA := sha256.Sum256(program)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, io.LimitReader(r.Body, (1<<20)+1))
		w.WriteHeader(200)
	}))
	defer upstream.Close()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	e := newEngine()
	e.rulePublicKey = public
	e.rulePool = newSecLangPool(binary, 1)
	defer e.rulePool.close()
	files, err := json.Marshal(input.Files)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(files)
	// The pinned upstream tests/docker-compose.yml uses DetectionOnly. Observe
	// preserves that forwarding intent; native incomplete checks still fail closed.
	site := Site{ID: "owned-http-corpus", Hostname: "localhost", Upstream: upstream.URL, Mode: "OBSERVE", Enabled: true, Version: 1}
	threshold := 0
	activate := func(next int) {
		site.RuleRelease = nil
		site.Version++
		payload, err := json.Marshal(secRuntimeRelease{SchemaVersion: 1, Engine: "selfguard-seclang-v1", BundleID: "frozen-crs-4.25.1", BundleSHA256: hex.EncodeToString(sum[:]), Threshold: next, Site: site, Files: files})
		if err != nil {
			t.Fatal(err)
		}
		site.RuleRelease = &secSignedRelease{Payload: base64.StdEncoding.EncodeToString(payload), Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(private, payload))}
		if err = e.update(Config{Sites: []Site{site}}); err != nil {
			t.Fatal(err)
		}
		threshold = next
	}
	server := httptest.NewUnstartedServer(e)
	server.Config.ReadHeaderTimeout = 5 * time.Second
	server.Config.ReadTimeout = 30 * time.Second
	server.Config.WriteTimeout = 30 * time.Second
	server.Config.IdleTimeout = 60 * time.Second
	server.Config.MaxHeaderBytes = 32768
	server.Start()
	defer server.Close()
	type observation struct {
		File            string `json:"file"`
		FileSHA256      string `json:"fileSha256"`
		RuleID          string `json:"ruleId"`
		TestID          int    `json:"testId"`
		Stage           int    `json:"stage"`
		RequestSHA256   string `json:"requestSha256"`
		Expected        []int  `json:"expectedStatuses"`
		CorpusThreshold int    `json:"corpusRuleThreshold"`
		Interim         []int  `json:"interimStatuses,omitempty"`
		Actual          int    `json:"actualStatus"`
		HandlerRequests uint64 `json:"handlerRequests"`
		Passed          bool   `json:"passed"`
		Error           string `json:"error,omitempty"`
	}
	rows := []observation{}
	for _, sample := range input.Cases {
		if sample.Threshold != 5 && sample.Threshold != 10000 {
			t.Fatal("unsupported corpus threshold")
		}
		if threshold == 0 {
			activate(5)
		}
		wire, decodeErr := base64.StdEncoding.DecodeString(sample.RequestBase64)
		if decodeErr != nil || len(wire) == 0 || len(wire) > 2<<20 || len(sample.ExpectedStatuses) == 0 || len(sample.ExpectedStatuses) > 10 {
			t.Fatal("invalid bounded original request")
		}
		for _, status := range sample.ExpectedStatuses {
			if status < 100 || status > 599 {
				t.Fatal("invalid original expected HTTP status")
			}
		}
		requestSHA := sha256.Sum256(wire)
		row := observation{File: sample.File, FileSHA256: sample.FileSHA256, RuleID: sample.RuleID, TestID: sample.TestID, Stage: sample.Stage, RequestSHA256: hex.EncodeToString(requestSHA[:]), Expected: sample.ExpectedStatuses, CorpusThreshold: sample.Threshold}
		before := e.totalRequests.Load()
		connection, dialErr := net.DialTimeout("tcp", server.Listener.Addr().String(), time.Second)
		if dialErr != nil {
			row.Error = "OWNED_HTTP_LISTENER_UNAVAILABLE"
		} else {
			connection.SetDeadline(time.Now().Add(35 * time.Second))
			if _, writeErr := connection.Write(wire); writeErr != nil {
				row.Error = "ORIGINAL_REQUEST_WRITE_FAILED"
			} else {
				reader := bufio.NewReader(connection)
				for count := 0; count < 8; count++ {
					response, readErr := http.ReadResponse(reader, nil)
					if readErr != nil {
						row.Error = "HTTP_RESPONSE_INCOMPLETE"
						break
					}
					if response.StatusCode >= 100 && response.StatusCode < 200 && response.StatusCode != 101 {
						row.Interim = append(row.Interim, response.StatusCode)
						response.Body.Close()
						continue
					}
					row.Actual = response.StatusCode
					if row.Actual != 101 {
						io.Copy(io.Discard, io.LimitReader(response.Body, 2<<20))
					}
					response.Body.Close()
					break
				}
				if row.Actual == 0 && row.Error == "" {
					row.Error = "INTERIM_RESPONSE_LIMIT"
				}
			}
			connection.Close()
		}
		row.HandlerRequests = e.totalRequests.Load() - before
		for _, expected := range row.Expected {
			if row.Error == "" && row.Actual == expected {
				row.Passed = true
			}
		}
		rows = append(rows, row)
		if !row.Passed {
			t.Errorf("original HTTP assertion differs: %s test %d stage %d expected %v, actual %d (%s)", row.File, row.TestID, row.Stage, row.Expected, row.Actual, row.Error)
		}
	}
	passed := 0
	for _, row := range rows {
		if row.Passed {
			passed++
		}
	}
	report := map[string]any{"archiveSha256": input.ArchiveSHA256, "engineSha256": hex.EncodeToString(programSHA[:]), "policySha256": hex.EncodeToString(sum[:]), "mode": "OBSERVE", "runtimeThreshold": 5, "upstreamFixtureMode": "DetectionOnly", "originalStatusAssertions": len(rows), "passed": passed, "failed": len(rows) - passed, "results": rows, "runtimePublished": false, "scope": "Real loopback HTTP responses through the signed frozen inbound policy, production threshold 5 and HTTP time/header limits; worker-only corpus thresholds are recorded separately; fixed 200 upstream. Worker rule-ID, score and log assertions remain in their independent report. HandlerRequests=0 identifies responses before the WAF handler; it does not establish a matched rule. Native incomplete inspection remains fail-closed even in observe mode."}
	encoded, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(outputPath, encoded, 0600); err != nil {
		t.Fatal(err)
	}
}
