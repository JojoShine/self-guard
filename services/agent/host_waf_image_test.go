package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHostWafImageArchiveRequiresExactScopeAndBytes(t *testing.T) {
	body := []byte("owned fixed image archive")
	sum := sha256.Sum256(body)
	digest := hex.EncodeToString(sum[:])
	var source string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		source = r.URL.String()
		if r.Header.Get("Authorization") != "Bearer owned-agent-token" {
			t.Error("missing exact platform credential")
		}
		w.Write(body)
	}))
	defer server.Close()
	a := &Agent{Config: Config{Server: server.URL + "/self-guard", AllowHTTP: true}, Client: server.Client(), Identity: Identity{Token: "owned-agent-token"}}
	p := HostWafPlan{ImageArchiveSHA256: digest, ImageArchiveBytes: int64(len(body))}
	var output bytes.Buffer
	if err := fetchHostWafImageArchive(a, p, &output); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(output.Bytes(), body) || source != "/self-guard/api/agent/host-waf/image?sha256="+digest {
		t.Fatal("wrong archive or platform path", source)
	}
	for _, change := range []HostWafPlan{{ImageArchiveSHA256: strings.Repeat("a", 64), ImageArchiveBytes: int64(len(body))}, {ImageArchiveSHA256: digest, ImageArchiveBytes: int64(len(body) - 1)}, {ImageArchiveSHA256: digest, ImageArchiveBytes: 65 << 20}} {
		if err := fetchHostWafImageArchive(a, change, &bytes.Buffer{}); err == nil {
			t.Fatal("invalid archive accepted")
		}
	}
	a.Config.AllowHTTP = false
	if err := fetchHostWafImageArchive(a, p, &bytes.Buffer{}); err == nil {
		t.Fatal("undeclared HTTP accepted")
	}
}
func TestHostWafImageArchiveNeverFollowsRedirects(t *testing.T) {
	var reached bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/next" {
			reached = true
		}
		http.Redirect(w, r, "/next", http.StatusFound)
	}))
	defer server.Close()
	a := &Agent{Config: Config{Server: server.URL, AllowHTTP: true}, Client: server.Client()}
	if err := fetchHostWafImageArchive(a, HostWafPlan{ImageArchiveSHA256: strings.Repeat("a", 64), ImageArchiveBytes: 10}, &bytes.Buffer{}); err == nil || reached {
		t.Fatal("redirect followed or accepted")
	}
}
