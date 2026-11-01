package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestRemoteRolloutTrustBoundsAndRollback(t *testing.T) {
	root, _ := filepath.EvalSymlinks(t.TempDir())
	os.WriteFile(filepath.Join(root, "current"), []byte("old fixture"), 0700)
	candidate := []byte("#!/bin/sh\nprintf 'selfguard-agent: healthy\\n'\n")
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(candidate) }))
	defer server.Close()
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	sum := sha256.Sum256(candidate)
	m := UpgradeManifest{Version: "0.2.0", Sequence: 1, SHA256: hex.EncodeToString(sum[:]), Size: int64(len(candidate)), OS: runtime.GOOS, Architecture: runtime.GOARCH, ExpiresAt: time.Now().Add(time.Hour)}
	raw, _ := json.Marshal(m)
	offer := RolloutOffer{ID: "fixture-target", ArtifactURL: server.URL, ManifestBytes: base64.StdEncoding.EncodeToString(raw), Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(key, raw))}
	a := &Agent{Config: Config{UpgradeInstallRoot: root, UpgradePublicKey: base64.StdEncoding.EncodeToString(pub)}, Client: server.Client()}
	if a.stageRemote(offer) == nil {
		t.Fatal("unconfigured artifact origin accepted")
	}
	a.Config.UpgradeOrigins = []string{server.URL}
	tampered := offer
	tampered.Signature = base64.StdEncoding.EncodeToString(make([]byte, 64))
	if a.stageRemote(tampered) == nil {
		t.Fatal("bad signature accepted")
	}
	if err := a.stageRemote(offer); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(filepath.Join(root, "current"))
	if string(got) != string(candidate) {
		t.Fatal("not staged")
	}
	if a.stageRemote(offer) == nil {
		t.Fatal("sequence replay accepted")
	}
	if err := rollbackUpgrade(a.Config); err != nil {
		t.Fatal(err)
	}
	got, _ = os.ReadFile(filepath.Join(root, "current"))
	if string(got) != "old fixture" {
		t.Fatal("rollback failed")
	}
}

func TestArtifactOriginPolicy(t *testing.T) {
	c := Config{UpgradeOrigins: []string{"https://releases.example.test"}}
	for _, value := range []string{"http://releases.example.test/a", "https://releases.example.test.evil/a", "https://user@releases.example.test/a", "https://releases.example.test:444/a"} {
		if trustedArtifact(c, value) == nil {
			t.Fatal("untrusted URL", value)
		}
	}
	if err := trustedArtifact(c, "https://releases.example.test/agent"); err != nil {
		t.Fatal(err)
	}
}

func TestRemoteArtifactBoundsRedirectAndFailedHealth(t *testing.T) {
	root, _ := filepath.EvalSymlinks(t.TempDir())
	os.WriteFile(filepath.Join(root, "current"), []byte("old fixture"), 0700)
	candidate := []byte("#!/bin/sh\nexit 1\n")
	response := candidate
	redirect := false
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			t.Error("artifact host received agent credentials")
		}
		if redirect {
			http.Redirect(w, r, "https://elsewhere.invalid/agent", 302)
			return
		}
		w.Write(response)
	}))
	defer server.Close()
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	sum := sha256.Sum256(candidate)
	m := UpgradeManifest{Version: "0.2.0", Sequence: 1, SHA256: hex.EncodeToString(sum[:]), Size: int64(len(candidate)), OS: runtime.GOOS, Architecture: runtime.GOARCH, ExpiresAt: time.Now().Add(time.Hour)}
	raw, _ := json.Marshal(m)
	offer := RolloutOffer{ID: "bounded", ArtifactURL: server.URL, ManifestBytes: base64.StdEncoding.EncodeToString(raw), Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(key, raw))}
	a := &Agent{Config: Config{UpgradeInstallRoot: root, UpgradePublicKey: base64.StdEncoding.EncodeToString(pub), UpgradeOrigins: []string{server.URL}}, Client: server.Client()}
	redirect = true
	if a.stageRemote(offer) == nil {
		t.Fatal("redirect accepted")
	}
	redirect = false
	response = append(append([]byte{}, candidate...), 1)
	if a.stageRemote(offer) == nil {
		t.Fatal("oversize accepted")
	}
	response = candidate
	if a.stageRemote(offer) == nil {
		t.Fatal("failed self-test accepted")
	}
	got, _ := os.ReadFile(filepath.Join(root, "current"))
	if string(got) != "old fixture" {
		t.Fatal("failed self-test did not restore old executable")
	}
}

func TestSameVersionRolloutStillRequiresProcessRestart(t *testing.T) {
	state := t.TempDir()
	posts := []string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			var body map[string]string
			json.NewDecoder(r.Body).Decode(&body)
			posts = append(posts, body["status"])
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"item":null}`))
	}))
	defer server.Close()
	raw, _ := json.Marshal(UpgradeManifest{Version: agentVersion})
	a := &Agent{Config: Config{StateDir: state, Server: server.URL, UpgradeInstallRoot: "configured", UpgradePublicKey: "configured", UpgradeOrigins: []string{"https://example.test"}}, Client: server.Client()}
	receipt := rolloutReceipt{Offer: RolloutOffer{ID: "same-version", ManifestBytes: base64.StdEncoding.EncodeToString(raw)}, Status: "STAGED", StagedBy: processInstance}
	writePrivate(filepath.Join(state, "rollout.json"), receipt)
	if err := a.rolloutCycle(); err != errUpgradeRestart {
		t.Fatal("same process acknowledged activation", err)
	}
	if len(posts) != 1 || posts[0] != "STAGED" {
		t.Fatal(posts)
	}
}
