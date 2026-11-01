package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestSignedFixtureUpgradeAndRollback(t *testing.T) {
	root, _ := filepath.EvalSymlinks(t.TempDir())
	os.WriteFile(filepath.Join(root, ".selfguard-upgrade-fixture"), []byte("offline fixture only\n"), 0600)
	target := filepath.Join(root, "current")
	os.WriteFile(target, []byte("old executable fixture"), 0700)
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	c := Config{UpgradeInstallRoot: root, UpgradePublicKey: base64.StdEncoding.EncodeToString(pub)}
	candidate := []byte("new executable fixture")
	hash := sha256.Sum256(candidate)
	m := UpgradeManifest{Version: "0.2.0", Sequence: 1, SHA256: hex.EncodeToString(hash[:]), Size: int64(len(candidate)), OS: runtime.GOOS, Architecture: runtime.GOARCH, ExpiresAt: time.Now().Add(time.Hour)}
	sign := func(m UpgradeManifest) SignedUpgrade {
		b, _ := json.Marshal(m)
		return SignedUpgrade{b, base64.StdEncoding.EncodeToString(ed25519.Sign(key, b))}
	}
	envelope := sign(m)
	healthCalls := 0
	health := func(p string) error {
		healthCalls++
		b, _ := os.ReadFile(p)
		if !bytes.Equal(b, candidate) {
			t.Fatal("wrong installed bytes")
		}
		return nil
	}
	bad := envelope
	bad.Signature = base64.StdEncoding.EncodeToString(make([]byte, 64))
	if stageUpgrade(c, bad, candidate, health) == nil {
		t.Fatal("bad signature accepted")
	}
	if stageUpgrade(c, envelope, []byte("tampered"), health) == nil {
		t.Fatal("bad content accepted")
	}
	expired := m
	expired.ExpiresAt = time.Now().Add(-time.Hour)
	if stageUpgrade(c, sign(expired), candidate, health) == nil {
		t.Fatal("expired accepted")
	}
	wrongTarget := m
	wrongTarget.Architecture = "unsupported"
	if stageUpgrade(c, sign(wrongTarget), candidate, health) == nil {
		t.Fatal("wrong architecture accepted")
	}
	if healthCalls != 0 {
		t.Fatal("unverified candidate executed")
	}
	if err := stageUpgrade(c, envelope, candidate, health); err != nil {
		t.Fatal(err)
	}
	if stageUpgrade(c, envelope, candidate, health) == nil {
		t.Fatal("replayed sequence accepted")
	}
	if err := rollbackUpgrade(c); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(target)
	if string(b) != "old executable fixture" {
		t.Fatal("rollback content")
	}
	if stageUpgrade(c, envelope, candidate, health) == nil {
		t.Fatal("rollback allowed signed downgrade replay")
	}
	m.Sequence = 2
	envelope = sign(m)
	if err := stageUpgrade(c, envelope, candidate, func(string) error { return errors.New("unhealthy") }); err == nil {
		t.Fatal("unhealthy succeeded")
	}
	b, _ = os.ReadFile(target)
	if string(b) != "old executable fixture" {
		t.Fatal("failed upgrade not rolled back")
	}
	if _, err := os.Stat(filepath.Join(root, "upgrade-recovery.json")); !os.IsNotExist(err) {
		t.Fatal("recovery marker retained after successful rollback")
	}
}
func TestFixtureRecoveryAndTrustRequired(t *testing.T) {
	root, _ := filepath.EvalSymlinks(t.TempDir())
	os.WriteFile(filepath.Join(root, "current"), []byte("old"), 0700)
	c := Config{UpgradeFixtureRoot: root}
	if stageUpgrade(c, SignedUpgrade{}, nil, func(string) error { return nil }) == nil {
		t.Fatal("missing marker accepted")
	}
	os.WriteFile(filepath.Join(root, ".selfguard-upgrade-fixture"), []byte("offline fixture only\n"), 0600)
	if stageUpgrade(c, SignedUpgrade{}, nil, func(string) error { return nil }) == nil {
		t.Fatal("missing trust accepted")
	}
	writePrivate(filepath.Join(root, "upgrade-recovery.json"), map[string]string{"status": "interrupted"})
	if stageUpgrade(c, SignedUpgrade{}, nil, func(string) error { return nil }) == nil {
		t.Fatal("interrupted upgrade did not stop")
	}
}

func TestSignedCandidateProcessAndStatus(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux executable fixture")
	}
	root, _ := filepath.EvalSymlinks(t.TempDir())
	os.WriteFile(filepath.Join(root, "current"), []byte("old fixture"), 0700)
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	c := Config{UpgradeInstallRoot: root, UpgradePublicKey: base64.StdEncoding.EncodeToString(pub)}
	candidate := []byte("#!/bin/sh\nprintf 'selfguard-agent: healthy\\n'\n")
	hash := sha256.Sum256(candidate)
	manifest := UpgradeManifest{Version: "0.2.0", Sequence: 1, SHA256: hex.EncodeToString(hash[:]), Size: int64(len(candidate)), OS: runtime.GOOS, Architecture: runtime.GOARCH, ExpiresAt: time.Now().Add(time.Hour)}
	b, _ := json.Marshal(manifest)
	envelope := SignedUpgrade{b, base64.StdEncoding.EncodeToString(ed25519.Sign(key, b))}
	if err := stageUpgrade(c, envelope, candidate, candidateHealth); err != nil {
		t.Fatal(err)
	}
	a := &Agent{Config: c}
	status := a.upgradeStatus().(map[string]any)
	if status["status"] != "STAGED_PENDING_RESTART" || status["path"] != filepath.Join(root, "current") {
		t.Fatal(status)
	}
	s, e := os.Stat(filepath.Join(root, "upgrade-status.json"))
	if e != nil || s.Mode().Perm() != 0644 {
		t.Fatal("status unreadable by service", e)
	}
	writePrivate(filepath.Join(root, "upgrade-recovery.json"), map[string]string{"status": "interrupted"})
	if e := a.cycle(); e == nil {
		t.Fatal("recovery did not pause agent")
	}
	if err := rollbackUpgrade(c); err != nil {
		t.Fatal(err)
	}
	actual, _ := os.ReadFile(filepath.Join(root, "current"))
	if string(actual) != "old fixture" {
		t.Fatal("fixture rollback")
	}
}
