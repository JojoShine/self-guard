//go:build linux

package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestPrivilegedExecutorSignedSocketBoundary(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("privileged fixture requires isolated root container")
	}
	root := t.TempDir()
	os.Chmod(root, 0700)
	managed := filepath.Join(root, "managed")
	os.Mkdir(managed, 0700)
	target := filepath.Join(managed, "file")
	os.WriteFile(target, []byte("fixture\n"), 0644)
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	uid := uint32(os.Getuid())
	socket := filepath.Join(root, "executor.sock")
	c := Config{StateDir: filepath.Join(root, "private"), AllowedRoot: managed, ExecutorSocket: socket, ExecutorPublicKey: base64.StdEncoding.EncodeToString(pub), ExecutorAssetID: "fixture-asset", ExecutorAllowedUID: &uid}
	server, err := newExecutor(c)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go server.serve(listener)
	sign := func(task Task) *TaskAuthorization {
		raw, _ := json.Marshal(task)
		return &TaskAuthorization{Payload: base64.StdEncoding.EncodeToString(raw), Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(key, raw))}
	}
	task := Task{ID: "signed", AssetID: "fixture-asset", Template: "FILE_PERMISSION", Parameters: Check{Path: target, Mode: "0600"}, ExpiresAt: time.Now().Add(time.Hour)}
	collector := &Agent{Config: Config{ExecutorSocket: socket}, Identity: Identity{AssetID: "fixture-asset"}}
	task.Authorization = sign(task)
	task.Authorization.Signature = base64.StdEncoding.EncodeToString(make([]byte, 64))
	if r := collector.execute(task); r.Success {
		t.Fatal("bad signature accepted")
	}
	task.Authorization = nil
	shortAuthorizationTask := task
	shortAuthorizationTask.ExpiresAt = time.Now().Add(4 * time.Minute)
	task.Authorization = sign(shortAuthorizationTask)
	if r := collector.execute(task); !r.Success {
		t.Fatal(r)
	}
	s, _ := os.Stat(target)
	if s.Mode().Perm() != 0600 {
		t.Fatal("approved mutation absent")
	}
	os.Chmod(target, 0640)
	if r := collector.execute(task); !r.Success {
		t.Fatal("retry did not return original receipt", r)
	}
	s, _ = os.Stat(target)
	if s.Mode().Perm() != 0640 {
		t.Fatal("replay mutated target")
	}
	fresh, err := newExecutor(c)
	if err != nil {
		t.Fatal(err)
	}
	if result := fresh.process(*task.Authorization); !result.Success {
		t.Fatal(result)
	}
	s, _ = os.Stat(target)
	if s.Mode().Perm() != 0640 {
		t.Fatal("durable replay mutated target")
	}
	bad := *task.Authorization
	bad.Signature = base64.StdEncoding.EncodeToString(make([]byte, 64))
	if result := fresh.process(bad); result.Success {
		t.Fatal("executor accepted invalid signature")
	}
	missing := c
	missing.ExecutorAllowedUID = nil
	if _, err := newExecutor(missing); err == nil {
		t.Fatal("executor UID default allowed")
	}

	task.ID = "wrong-asset"
	task.AssetID = "other"
	task.Authorization = nil
	task.Authorization = sign(task)
	if r := collector.execute(task); r.Success {
		t.Fatal("wrong asset accepted")
	}
	if result := fresh.process(*task.Authorization); result.Success {
		t.Fatal("root executor accepted wrong asset")
	}
	task.AssetID = "fixture-asset"
	task.ID = "expired"
	task.ExpiresAt = time.Now().Add(-time.Second)
	task.Authorization = nil
	task.Authorization = sign(task)
	if result := fresh.process(*task.Authorization); result.Success {
		t.Fatal("root executor accepted expired task")
	}

	unavailable := &Agent{Config: Config{ExecutorSocket: filepath.Join(root, "missing.sock"), AllowedRoot: managed}}
	task.Template = "FILE_PERMISSION"
	task.Parameters.Mode = "0600"
	if r := unavailable.execute(task); r.Success || !strings.Contains(r.Evidence, "executor") {
		t.Fatal("fallback accepted", r)
	}
	s, _ = os.Stat(target)
	if s.Mode().Perm() != 0640 {
		t.Fatal("fallback mutated")
	}
}

func TestExecutorUnprivilegedCollectorProcess(t *testing.T) {
	if os.Getenv("EXECUTOR_CHILD_FIXTURE") == "true" {
		raw, _ := base64.StdEncoding.DecodeString(os.Getenv("EXECUTOR_CHILD_TASK"))
		var task Task
		if err := json.Unmarshal(raw, &task); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(task.Parameters.Path, 0600); err == nil {
			t.Fatal("unprivileged collector directly changed root fixture")
		}
		if _, err := os.ReadFile(os.Getenv("EXECUTOR_CHILD_PRIVATE_KEY")); err == nil {
			t.Fatal("collector could read executor signing key")
		}

		a := &Agent{Config: Config{ExecutorSocket: os.Getenv("EXECUTOR_CHILD_SOCKET")}, Identity: Identity{AssetID: task.AssetID}}
		result := a.execute(task)
		if !result.Success {
			t.Fatal(result)
		}
		return
	}
	if os.Geteuid() != 0 {
		t.Skip("isolated root container fixture")
	}
	root := t.TempDir()
	os.Chmod(filepath.Dir(root), 0755)
	os.Chmod(root, 0755)
	managed := filepath.Join(root, "managed")
	os.Mkdir(managed, 0700)
	target := filepath.Join(managed, "file")
	os.WriteFile(target, []byte("root fixture"), 0644)
	uid := uint32(65534)
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	socket := filepath.Join(root, "executor.sock")
	c := Config{StateDir: filepath.Join(root, "root-private"), AllowedRoot: managed, ExecutorSocket: socket, ExecutorPublicKey: base64.StdEncoding.EncodeToString(pub), ExecutorAssetID: "fixture-asset", ExecutorAllowedUID: &uid}
	config := filepath.Join(root, "executor.json")
	if err := writePrivate(config, c); err != nil {
		t.Fatal(err)
	}
	executorBinary := filepath.Join(root, "root-executor")
	build := exec.Command("go", "build", "-o", executorBinary, ".")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build CLI: %v: %s", err, output)
	}
	command := exec.Command(executorBinary, "--executor")
	command.Env = append(os.Environ(), "AGENT_CONFIG="+config)
	var executorOutput bytes.Buffer
	command.Stdout = &executorOutput
	command.Stderr = &executorOutput
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		command.Process.Signal(os.Interrupt)
		if err := command.Wait(); err != nil {
			t.Errorf("executor CLI: %v: %s", err, executorOutput.String())
		}
	}()
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := os.Stat(socket); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("executor socket startup timeout")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := os.Chown(socket, 0, 65534); err != nil {
		t.Fatal(err)
	}
	publicCommand := exec.Command(executorBinary, "--executor-public-key")
	publicCommand.Env = append(os.Environ(), "AGENT_CONFIG="+config)
	publicOutput, err := publicCommand.Output()
	if err != nil {
		t.Fatal(err)
	}
	exported, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(publicOutput)))
	if err != nil || len(exported) != ed25519.PublicKeySize {
		t.Fatal("public-key CLI output invalid")
	}
	if info, err := os.Stat(socket); err != nil || info.Mode().Perm() != 0660 {
		t.Fatal("executor socket permissions", err)
	}
	task := Task{ID: "unprivileged-approved", AssetID: "fixture-asset", Template: "FILE_PERMISSION", Parameters: Check{Path: target, Mode: "0600"}, ExpiresAt: time.Now().Add(time.Hour)}
	raw, _ := json.Marshal(task)
	task.Authorization = &TaskAuthorization{Payload: base64.StdEncoding.EncodeToString(raw), Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(key, raw))}
	request, _ := json.Marshal(task)
	// A root peer is not the configured collector UID, even with valid signed authorization.
	rootCaller := &Agent{Config: Config{ExecutorSocket: socket}, Identity: Identity{AssetID: task.AssetID}}
	if result := rootCaller.execute(task); result.Success {
		t.Fatal("wrong peer UID accepted")
	}
	executable, _ := os.Executable()
	binary := filepath.Join(root, "collector-fixture")
	bytes, err := os.ReadFile(executable)
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(binary, bytes, 0755)
	child := exec.Command(binary, "-test.run=^TestExecutorUnprivilegedCollectorProcess$")
	child.Env = append(os.Environ(), "EXECUTOR_CHILD_FIXTURE=true", "EXECUTOR_CHILD_TASK="+base64.StdEncoding.EncodeToString(request), "EXECUTOR_CHILD_SOCKET="+socket, "EXECUTOR_CHILD_PRIVATE_KEY="+filepath.Join(c.StateDir, "executor-result-key.bin"))
	child.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65534, Gid: 65534}}
	if output, err := child.CombinedOutput(); err != nil {
		t.Fatalf("unprivileged process: %v: %s", err, output)
	}
	info, _ := os.Stat(target)
	if info.Mode().Perm() != 0600 {
		t.Fatal("signed privileged mutation did not occur")
	}
}

func TestExecutorRejectsUnprotectedConfigAncestors(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("isolated root fixture")
	}
	root := t.TempDir()
	unsafe := filepath.Join(root, "writable")
	os.Mkdir(unsafe, 0777)
	os.Chmod(unsafe, 0777)
	config := filepath.Join(unsafe, "executor.json")
	os.WriteFile(config, []byte("{}"), 0600)
	if err := executorTrustedConfig(config); err == nil {
		t.Fatal("writable config ancestor accepted")
	}
	if err := executorTrustedDirectory(unsafe, false); err == nil {
		t.Fatal("writable executor parent accepted")
	}
}

func TestExecutorSignsDurableResultProof(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root fixture")
	}
	root := t.TempDir()
	managed := filepath.Join(root, "managed")
	os.Mkdir(managed, 0700)
	target := filepath.Join(managed, "file")
	os.WriteFile(target, []byte("fixture"), 0644)
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	uid := uint32(0)
	c := Config{StateDir: filepath.Join(root, "private"), AllowedRoot: managed, ExecutorSocket: filepath.Join(root, "socket"), ExecutorPublicKey: base64.StdEncoding.EncodeToString(pub), ExecutorAssetID: "signed-result-asset", ExecutorAllowedUID: &uid}
	server, err := newExecutor(c)
	if err != nil {
		t.Fatal(err)
	}
	task := Task{ID: "proof-task", AssetID: c.ExecutorAssetID, Template: "FILE_PERMISSION", Parameters: Check{Path: target, Mode: "0600"}, ExpiresAt: time.Now().Add(time.Hour)}
	raw, _ := json.Marshal(task)
	auth := TaskAuthorization{Payload: base64.StdEncoding.EncodeToString(raw), Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(key, raw))}
	result := server.process(auth)
	var proof TaskAuthorization
	if err := json.Unmarshal([]byte(result.Details["executorProof"]), &proof); err != nil {
		t.Fatal("executor proof missing", err)
	}
	private, err := os.ReadFile(filepath.Join(c.StateDir, "executor-result-key.bin"))
	if err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(filepath.Join(c.StateDir, "executor-result-key.bin"))
	if info.Mode().Perm() != 0600 {
		t.Fatal("private result key exposed")
	}
	payload, _ := base64.StdEncoding.DecodeString(proof.Payload)
	signature, _ := base64.StdEncoding.DecodeString(proof.Signature)
	resultPublic := ed25519.PrivateKey(private).Public().(ed25519.PublicKey)
	if !ed25519.Verify(resultPublic, payload, signature) {
		t.Fatal("invalid proof")
	}
	var body struct {
		TaskID  string `json:"taskId"`
		AssetID string `json:"assetId"`
		Result  Result `json:"result"`
	}
	if json.Unmarshal(payload, &body) != nil || body.TaskID != task.ID || body.AssetID != task.AssetID || !body.Result.Success || body.Result.Details["executorProof"] != "" {
		t.Fatal("result proof binding invalid")
	}
	tampered := append([]byte{}, payload...)
	tampered[len(tampered)-2] ^= 1
	if ed25519.Verify(resultPublic, tampered, signature) {
		t.Fatal("tampered proof valid")
	}
	fresh, err := newExecutor(c)
	if err != nil {
		t.Fatal(err)
	}
	replay := fresh.process(auth)
	if replay.Details["executorProof"] != result.Details["executorProof"] {
		t.Fatal("cached replay proof changed or signing key lost")
	}
}

func TestExecutorPublicKeyExportDoesNotReconcileUpgrade(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root fixture")
	}
	root := t.TempDir()
	state := filepath.Join(root, "private")
	os.Mkdir(state, 0700)
	install := filepath.Join(root, "install")
	os.Mkdir(install, 0755)
	os.WriteFile(filepath.Join(install, "current"), []byte("new signed fixture"), 0755)
	config := Config{StateDir: state, UpgradeInstallRoot: install}
	configPath := filepath.Join(root, "executor.json")
	writePrivate(configPath, config)
	t.Setenv("AGENT_CONFIG", configPath)
	writePrivate(filepath.Join(state, "executor-receipts.json"), map[string]executorReceipt{"upgrade": {Template: "UPGRADE", Result: Result{Success: true, Details: map[string]string{"upgradeStaged": "true", "upgradeVersion": "0.2.0", "stageProcess": "prior-process"}}}})
	writePrivate(filepath.Join(install, "installed.json"), UpgradeManifest{Version: "0.2.0"})
	writePrivate(filepath.Join(install, "upgrade-backup.json"), upgradeBackup{Content: []byte("old fixture"), Mode: 0755, Previous: UpgradeManifest{Version: "0.1.0"}})
	key, err := executorPublicKey(config)
	if err != nil || len(key) != 44 {
		t.Fatal("public-key export failed", err)
	}
	current, _ := os.ReadFile(filepath.Join(install, "current"))
	if string(current) != "new signed fixture" {
		t.Fatal("public-key export changed installation")
	}
}
