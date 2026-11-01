//go:build linux

package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestDelegatedUpgradeRealProcesses(t *testing.T) {
	if os.Getenv("UPGRADE_COLLECTOR_CHILD") == "true" {
		raw, _ := base64.StdEncoding.DecodeString(os.Getenv("UPGRADE_OFFER"))
		var offer RolloutOffer
		if json.Unmarshal(raw, &offer) != nil {
			t.Fatal("offer decode")
		}
		if err := os.WriteFile(os.Getenv("UPGRADE_CURRENT"), []byte("unauthorized"), 0755); err == nil {
			t.Fatal("unprivileged collector directly staged")
		}
		collector := &Agent{Config: Config{ExecutorSocket: os.Getenv("UPGRADE_SOCKET")}, Identity: Identity{AssetID: "upgrade-asset"}}
		result := collector.delegatedUpgrade(offer)
		expected := os.Getenv("UPGRADE_EXPECT_SUCCESS") == "true"
		if result.Success != expected {
			t.Fatal(result)
		}
		if expected {
			if result.Details["executorVersion"] != os.Getenv("UPGRADE_EXPECT_VERSION") {
				t.Fatal("wrong executor process version", result)
			}
			if result.Details["executorProof"] == "" {
				t.Fatal("unsigned delegated upgrade result")
			}
		}
		return
	}
	if os.Geteuid() != 0 {
		t.Skip("isolated privileged Linux fixture")
	}
	root := t.TempDir()
	os.Chmod(filepath.Dir(root), 0755)
	os.Chmod(root, 0755)
	install := filepath.Join(root, "install")
	os.Mkdir(install, 0755)
	socket := filepath.Join(root, "executor.sock")
	state := filepath.Join(root, "private")
	old := filepath.Join(install, "current")
	next := filepath.Join(root, "next-agent")
	for _, build := range []struct{ version, path string }{{"0.1.0", old}, {"0.2.0", next}} {
		cmd := exec.Command("go", "build", "-ldflags", "-X main.agentVersion="+build.version, "-o", build.path, ".")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("build: %v %s", err, out)
		}
	}
	candidate, _ := os.ReadFile(next)
	tls := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			t.Error("artifact credentials leaked")
		}
		w.Write(candidate)
	}))
	defer tls.Close()
	taskPub, taskKey, _ := ed25519.GenerateKey(rand.Reader)
	releasePub, releaseKey, _ := ed25519.GenerateKey(rand.Reader)
	uid := uint32(65534)
	config := Config{StateDir: state, ExecutorSocket: socket, ExecutorAssetID: "upgrade-asset", ExecutorAllowedUID: &uid, ExecutorPublicKey: base64.StdEncoding.EncodeToString(taskPub), UpgradeInstallRoot: install, UpgradePublicKey: base64.StdEncoding.EncodeToString(releasePub), UpgradeOrigins: []string{tls.URL}, CACertificate: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: tls.Certificate().Raw}))}
	cfg := filepath.Join(root, "executor.json")
	writePrivate(cfg, config)
	start := func() *exec.Cmd {
		cmd := exec.Command(old, "--executor")
		cmd.Env = append(os.Environ(), "AGENT_CONFIG="+cfg)
		mask := syscall.Umask(0077)
		startErr := cmd.Start()
		syscall.Umask(mask)
		if startErr != nil {
			t.Fatal(startErr)
		}
		deadline := time.Now().Add(10 * time.Second)
		for {
			if _, err := os.Stat(socket); err == nil {
				break
			}
			if time.Now().After(deadline) {
				cmd.Process.Kill()
				t.Fatal("executor socket timeout")
			}
			time.Sleep(10 * time.Millisecond)
		}
		os.Chown(socket, 0, 65534)
		return cmd
	}
	executor := start()
	defer func() {
		if executor.ProcessState == nil {
			executor.Process.Signal(os.Interrupt)
			executor.Wait()
		}
	}()
	sum := sha256.Sum256(candidate)
	manifest, _ := json.Marshal(UpgradeManifest{Version: "0.2.0", Sequence: 1, SHA256: hex.EncodeToString(sum[:]), Size: int64(len(candidate)), OS: runtime.GOOS, Architecture: runtime.GOARCH, ExpiresAt: time.Now().Add(time.Hour)})
	offer := RolloutOffer{ID: "upgrade-target", ArtifactURL: tls.URL, ManifestBytes: base64.StdEncoding.EncodeToString(manifest), Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(releaseKey, manifest))}
	authorize := func(offer RolloutOffer, asset string) *TaskAuthorization {
		params, _ := json.Marshal(upgradeCommand{offer.ArtifactURL, offer.ManifestBytes, offer.Signature, offer.DownloadGrant})
		payload, _ := json.Marshal(executorPayload{ID: offer.ID, AssetID: asset, Template: "UPGRADE", Parameters: params, ExpiresAt: time.Now().Add(4 * time.Minute)})
		return &TaskAuthorization{Payload: base64.StdEncoding.EncodeToString(payload), Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(taskKey, payload))}
	}
	testExecutable, _ := os.Executable()
	driver := filepath.Join(root, "collector-driver")
	testBytes, _ := os.ReadFile(testExecutable)
	os.WriteFile(driver, testBytes, 0755)
	call := func(offer RolloutOffer, expected bool, version string) {
		raw, _ := json.Marshal(offer)
		cmd := exec.Command(driver, "-test.run=^TestDelegatedUpgradeRealProcesses$")
		cmd.Env = append(os.Environ(), "UPGRADE_COLLECTOR_CHILD=true", "UPGRADE_OFFER="+base64.StdEncoding.EncodeToString(raw), "UPGRADE_CURRENT="+old, "UPGRADE_SOCKET="+socket, "UPGRADE_EXPECT_SUCCESS="+strings.ToLower(map[bool]string{true: "true", false: "false"}[expected]), "UPGRADE_EXPECT_VERSION="+version)
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65534, Gid: 65534}}
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("collector: %v %s", err, out)
		}
	}
	bad := offer
	bad.ID = "wrong-origin"
	bad.ArtifactURL = "https://untrusted.invalid/release"
	bad.Authorization = authorize(bad, "upgrade-asset")
	call(bad, false, "")
	bad = offer
	bad.ID = "wrong-release"
	bad.Signature = base64.StdEncoding.EncodeToString(make([]byte, 64))
	bad.Authorization = authorize(bad, "upgrade-asset")
	call(bad, false, "")
	bad = offer
	bad.ID = "wrong-asset"
	bad.Authorization = authorize(bad, "other-asset")
	call(bad, false, "")
	missingKey := config
	missingKey.UpgradePublicKey = ""
	missingKey.StateDir = filepath.Join(root, "missing-key-state")
	missingExecutor, err := newExecutor(missingKey)
	if err != nil {
		t.Fatal(err)
	}
	missingExecutor.agent.Client = tls.Client()
	probe := offer
	probe.ID = "missing-release-key"
	probe.Authorization = authorize(probe, "upgrade-asset")
	if result := missingExecutor.process(*probe.Authorization); result.Success {
		t.Fatal("missing release trust key staged")
	}
	offer.Authorization = authorize(offer, "upgrade-asset")
	call(offer, true, "0.1.0")
	err = executor.Wait()
	exit, ok := err.(*exec.ExitError)
	if !ok || exit.ExitCode() != 75 {
		t.Fatal("executor did not restart after acknowledged staging", err)
	}
	installed, _ := os.ReadFile(old)
	if !strings.EqualFold(hex.EncodeToString(sha256Digest(installed)), hex.EncodeToString(sum[:])) {
		t.Fatal("installed release mismatch")
	}
	info, _ := os.Stat(old)
	if info.Mode().Perm() != 0755 {
		t.Fatal("collector cannot execute new shared slot")
	}
	executor = start()
	call(offer, true, "0.2.0")
	versions := make(chan string, 1)
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/agent/enroll":
			w.Write([]byte(`{"assetId":"upgrade-asset","token":"fixture"}`))
		case "/api/agent/heartbeat":
			var body struct {
				Inventory struct {
					Diagnostics struct {
						Version string `json:"version"`
					} `json:"agentDiagnostics"`
				} `json:"inventory"`
			}
			json.NewDecoder(r.Body).Decode(&body)
			select {
			case versions <- body.Inventory.Diagnostics.Version:
			default:
			}
			w.Write([]byte(`{}`))
		case "/api/agent/policy":
			w.Write([]byte(`{"rules":[]}`))
		case "/api/agent/tasks":
			w.Write([]byte(`{"items":[]}`))
		default:
			w.Write([]byte(`{}`))
		}
	}))
	defer api.Close()
	collectorState := filepath.Join(root, "collector-state")
	os.Mkdir(collectorState, 0700)
	os.Chown(collectorState, 65534, 65534)
	collectorConfig := filepath.Join(root, "collector.json")
	rawConfig, _ := json.Marshal(Config{Server: api.URL, StateDir: collectorState, ExecutorSocket: socket})
	os.WriteFile(collectorConfig, rawConfig, 0644)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	collector := exec.CommandContext(ctx, old)
	collector.Env = append(os.Environ(), "AGENT_CONFIG="+collectorConfig)
	collector.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65534, Gid: 65534}}
	if err := collector.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { collector.Process.Kill(); collector.Wait() }()
	select {
	case version := <-versions:
		if version != "0.2.0" {
			t.Fatal("new unprivileged collector version", version)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("new collector heartbeat absent")
	}
}
func sha256Digest(b []byte) []byte { s := sha256.Sum256(b); return s[:] }
