package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"
)

type TaskAuthorization struct {
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}
type executorPayload struct {
	ID         string          `json:"id"`
	AssetID    string          `json:"assetId"`
	Template   string          `json:"template"`
	Parameters json.RawMessage `json:"parameters"`
	ExpiresAt  time.Time       `json:"expiresAt"`
}
type executorReceipt struct {
	Template string
	Hash     string
	Result   Result
}
type privilegedExecutor struct {
	resultKey ed25519.PrivateKey
	agent     *Agent
	key       ed25519.PublicKey
	assetID   string
	uid       uint32
	receipts  map[string]executorReceipt
}

func (a *Agent) executeViaExecutor(t Task) Result {
	if t.Authorization == nil {
		return Result{Evidence: "signed executor authorization required"}
	}
	raw, decodeErr := base64.StdEncoding.DecodeString(t.Authorization.Payload)
	var authorized executorPayload
	if decodeErr != nil || json.Unmarshal(raw, &authorized) != nil || authorized.ID != t.ID || authorized.AssetID != a.Identity.AssetID || authorized.Template != t.Template || !authorized.ExpiresAt.After(time.Now()) || authorized.ExpiresAt.After(t.ExpiresAt) {
		return Result{Evidence: "executor authorization does not match claimed task"}
	}
	var parameters Check
	if decodeExecutorParameters(authorized.Parameters, &parameters) != nil || parameters != t.Parameters {
		return Result{Evidence: "executor parameters do not match claimed task"}
	}
	return a.executorRequest(t.Authorization, 30*time.Second)
}
func decodeExecutorParameters(raw json.RawMessage, out any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(out); err != nil {
		return err
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return errors.New("trailing executor parameters")
	}
	return nil
}
func (a *Agent) executorRequest(authorization *TaskAuthorization, timeout time.Duration) Result {
	connection, err := net.DialTimeout("unix", a.Config.ExecutorSocket, 3*time.Second)
	if err != nil {
		return Result{Evidence: "privileged executor unavailable; no local fallback"}
	}
	defer connection.Close()
	connection.SetDeadline(time.Now().Add(timeout))
	if err = json.NewEncoder(connection).Encode(authorization); err != nil {
		return Result{Evidence: "executor delivery failed", Details: map[string]string{"resultUnknown": "true"}}
	}
	var result Result
	if err = json.NewDecoder(io.LimitReader(connection, 128<<10)).Decode(&result); err != nil {
		return Result{Evidence: "executor response unavailable", Details: map[string]string{"resultUnknown": "true"}}
	}
	if result.Success && result.Details["upgradeStaged"] == "true" {
		json.NewEncoder(connection).Encode(map[string]bool{"ack": true})
	}
	return result
}
func newExecutor(c Config) (*privilegedExecutor, error) {
	if err := executorPlatform(); err != nil {
		return nil, err
	}
	if c.ExecutorAllowedUID == nil || c.ExecutorAssetID == "" || len(c.ExecutorAssetID) > 200 || c.ExecutorSocket == "" || c.StateDir == "" {
		return nil, errors.New("executor asset, socket, allowed UID and private state required")
	}
	if !filepath.IsAbs(c.StateDir) || !filepath.IsAbs(c.ExecutorSocket) || (c.AllowedRoot != "" && !filepath.IsAbs(c.AllowedRoot)) {
		return nil, errors.New("executor paths must be absolute")
	}
	key, err := base64.StdEncoding.DecodeString(c.ExecutorPublicKey)
	if err != nil || len(key) != ed25519.PublicKeySize {
		return nil, errors.New("executor Ed25519 public key required")
	}
	if err = executorTrustedDirectory(filepath.Dir(c.StateDir), false); err != nil {
		return nil, err
	}
	if err = os.MkdirAll(c.StateDir, 0700); err != nil {
		return nil, err
	}
	if err = executorTrustedDirectory(c.StateDir, true); err != nil {
		return nil, err
	}
	if c.AllowedRoot != "" {
		if err = executorTrustedDirectory(c.AllowedRoot, false); err != nil {
			return nil, err
		}
	}
	if err = executorTrustedDirectory(filepath.Dir(c.ExecutorSocket), false); err != nil {
		return nil, err
	}
	local := c
	local.ExecutorSocket = ""
	client, err := clientForConfig(c)
	if err != nil {
		return nil, err
	}
	worker := &Agent{Config: local, Done: map[string]Result{}, Client: client}
	executor := &privilegedExecutor{agent: worker, key: key, assetID: c.ExecutorAssetID, uid: *c.ExecutorAllowedUID, receipts: map[string]executorReceipt{}}
	if err = read(filepath.Join(c.StateDir, "executor-receipts.json"), &executor.receipts); err != nil {
		return nil, err
	}
	executor.resultKey, err = executorResultKey(c.StateDir)
	if err != nil {
		return nil, err
	}
	for id, receipt := range executor.receipts {
		worker.Done[id] = receipt.Result
	}
	if err = executor.recoverExecutorVersion(); err != nil {
		return nil, err
	}
	return executor, nil
}
func (e *privilegedExecutor) processAuthorized(auth TaskAuthorization) Result {
	fail := func(message string) Result { return Result{Evidence: message} }
	if err := executorTrustedDirectory(e.agent.Config.StateDir, true); err != nil {
		return fail("executor private state protection lost")
	}
	if e.agent.Config.AllowedRoot != "" {
		if err := executorTrustedDirectory(e.agent.Config.AllowedRoot, false); err != nil {
			return fail("executor managed root protection lost")
		}
	}
	raw, err := base64.StdEncoding.DecodeString(auth.Payload)
	if err != nil || len(raw) > 64<<10 {
		return fail("invalid executor payload")
	}
	signature, err := base64.StdEncoding.DecodeString(auth.Signature)
	if err != nil || !ed25519.Verify(e.key, raw, signature) {
		return fail("invalid executor signature")
	}
	var payload executorPayload
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&payload); err != nil {
		return fail("invalid executor task")
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return fail("trailing executor task data")
	}
	if payload.ID == "" || len(payload.ID) > 200 || payload.AssetID != e.assetID || !payload.ExpiresAt.After(time.Now()) {
		return fail("executor target or expiry mismatch")
	}
	switch payload.Template {
	case "FILE_PERMISSION", "CONFIG_VALUE", "SERVICE_STATE", "ROLLBACK", "VERIFY_READ", "UPGRADE":
	default:
		return fail("executor template not allowed")
	}
	for _, receipt := range e.receipts {
		if receipt.Template == "UPGRADE" && receipt.Result.Details["resultUnknown"] == "true" {
			return Result{Evidence: "executor upgrade outcome unknown; reconcile installation and private receipt", Details: map[string]string{"resultUnknown": "true"}}
		}
	}
	digest := fmt.Sprintf("%x", sha256.Sum256(raw))
	if receipt, ok := e.receipts[payload.ID]; ok {
		if receipt.Hash != digest {
			return fail("executor task ID reused with different authorization")
		}
		return receipt.Result
	}
	if payload.Template != "VERIFY_READ" && e.agent.Config.UpgradeInstallRoot == "/opt/selfguard-agent" {
		unlock, lockErr := waitInstallationFile("/opt/selfguard-agent/operation.lock", 35*time.Second)
		if lockErr != nil {
			return fail("installation or recovery already active; mutation not started")
		}
		defer unlock()
		if !payload.ExpiresAt.After(time.Now()) {
			return fail("executor authorization expired while waiting for installation")
		}
		if err = unfinishedInstallationTransactions(); err != nil {
			return fail("unfinished local installation requires recovery before mutation")
		}
	}
	if payload.Template != "VERIFY_READ" {
		for _, marker := range []string{"service-recovery.json", "config-recovery.json"} {
			if _, err := os.Stat(filepath.Join(e.agent.Config.StateDir, marker)); !os.IsNotExist(err) {
				return Result{Evidence: "executor recovery pending; operator reconciliation required", Details: map[string]string{"resultUnknown": "true"}}
			}
		}
	}
	if len(e.receipts) >= 10000 {
		return fail("executor receipt capacity reached")
	}
	receiptPath := filepath.Join(e.agent.Config.StateDir, "executor-receipts.json")
	unknown := Result{Evidence: "executor execution interrupted; reconcile before retry", Details: map[string]string{"resultUnknown": "true"}}
	e.receipts[payload.ID] = executorReceipt{Hash: digest, Result: unknown, Template: payload.Template}
	if err = writePrivate(receiptPath, e.receipts); err != nil {
		delete(e.receipts, payload.ID)
		return fail("executor intent persistence failed")
	}
	var result Result
	if payload.Template == "UPGRADE" {
		result = e.stageExecutorUpgrade(payload)
	} else {
		var parameters Check
		if err := decodeExecutorParameters(payload.Parameters, &parameters); err != nil {
			result = fail("invalid signed task parameters")
		} else {
			result = e.agent.execute(Task{ID: payload.ID, AssetID: payload.AssetID, Template: payload.Template, Parameters: parameters, ExpiresAt: payload.ExpiresAt})
		}
	}
	e.receipts[payload.ID] = executorReceipt{Hash: digest, Result: result, Template: payload.Template}
	e.agent.Done[payload.ID] = result
	if err = writePrivate(receiptPath, e.receipts); err != nil {
		e.receipts[payload.ID] = executorReceipt{Hash: digest, Result: unknown, Template: payload.Template}
		e.agent.Done[payload.ID] = unknown
		return unknown
	}
	return result
}
func (e *privilegedExecutor) serve(listener net.Listener) error {
	for {
		connection, err := listener.Accept()
		if err != nil {
			return err
		}
		connection.SetDeadline(time.Now().Add(30 * time.Second))
		restart := false
		func() {
			defer connection.Close()
			if err := executorPeer(connection, e.uid); err != nil {
				json.NewEncoder(connection).Encode(Result{Evidence: "executor peer UID refused"})
				return
			}
			var auth TaskAuthorization
			decoder := json.NewDecoder(io.LimitReader(connection, 128<<10))
			decoder.DisallowUnknownFields()
			if err := decoder.Decode(&auth); err != nil {
				json.NewEncoder(connection).Encode(Result{Evidence: "invalid executor request"})
				return
			}
			connection.SetDeadline(time.Now().Add(3 * time.Minute))
			result := e.process(auth)
			if err := json.NewEncoder(connection).Encode(result); err != nil {
				return
			}
			if result.Success && result.Details["upgradeStaged"] == "true" && result.Details["stageProcess"] == processInstance {
				var ack struct {
					Ack bool `json:"ack"`
				}
				connection.SetReadDeadline(time.Now().Add(5 * time.Second))
				if json.NewDecoder(io.LimitReader(connection, 512)).Decode(&ack) == nil && ack.Ack {
					restart = true
				}
			}
		}()
		if restart {
			return errUpgradeRestart
		}
	}
}
func runExecutor(c Config) error {
	if err := executorTrustedConfig(os.Getenv("AGENT_CONFIG")); err != nil {
		return err
	}
	executor, err := newExecutor(c)
	if err != nil {
		return err
	}
	// Never unlink an existing socket: a stale installation requires operator reconciliation.
	listener, err := net.Listen("unix", c.ExecutorSocket)
	if err != nil {
		return err
	}
	defer listener.Close()
	if err = os.Chmod(c.ExecutorSocket, 0660); err != nil {
		return err
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	go func() { <-ctx.Done(); listener.Close() }()
	err = executor.serve(listener)
	if ctx.Err() != nil {
		return nil
	}
	return err
}
