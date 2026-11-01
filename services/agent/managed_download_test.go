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
	"strings"
	"testing"
	"time"
)

func TestManagedArtifactGrantDoesNotForwardCollectorCredentialsOrLeaveItsBoundRoute(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "current"), []byte("old fixture"), 0700); err != nil {
		t.Fatal(err)
	}
	candidate := []byte("#!/bin/sh\nprintf 'selfguard-agent: healthy\\n'\n")
	grant := &TaskAuthorization{Payload: "download-only-payload", Signature: "download-only-signature"}
	encoded, _ := json.Marshal(grant)
	calls := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Header.Get("Authorization") != "SelfGuardDownload "+base64.StdEncoding.EncodeToString(encoded) || strings.Contains(r.Header.Get("Authorization"), "collector-secret") {
			t.Error("download grant missing or collector credentials forwarded")
		}
		w.Write(candidate)
	}))
	defer server.Close()
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	digest := sha256.Sum256(candidate)
	manifest := UpgradeManifest{Version: "0.3.0", Sequence: 1, SHA256: hex.EncodeToString(digest[:]), Size: int64(len(candidate)), OS: runtime.GOOS, Architecture: runtime.GOARCH, ExpiresAt: time.Now().Add(time.Hour)}
	raw, _ := json.Marshal(manifest)
	offer := RolloutOffer{ID: "grant-target", ArtifactURL: server.URL + "/api/agent/rollout/grant-target/artifact", ManifestBytes: base64.StdEncoding.EncodeToString(raw), Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(key, raw)), DownloadGrant: grant}
	a := &Agent{Config: Config{Server: "https://other.invalid", UpgradeInstallRoot: root, UpgradePublicKey: base64.StdEncoding.EncodeToString(pub), UpgradeOrigins: []string{server.URL}}, Identity: Identity{Token: "collector-secret"}, Client: server.Client()}
	if err := a.stageRemote(offer); err == nil || calls != 0 {
		t.Fatal("grant sent outside configured platform")
	}
	a.Config.Server = server.URL
	wrong := offer
	wrong.ArtifactURL = server.URL + "/other-route"
	if err := a.stageRemote(wrong); err == nil || calls != 0 {
		t.Fatal("grant sent to unbound route")
	}
	if err := a.stageRemote(offer); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatal("unexpected artifact request count")
	}
}
