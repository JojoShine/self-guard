package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
)

func executorResultKey(root string) (ed25519.PrivateKey, error) {
	path := filepath.Join(root, "executor-result-key.bin")
	_, generated, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err == nil {
		_, err = file.Write(generated)
		if err == nil {
			err = file.Sync()
		}
		closed := file.Close()
		if err != nil {
			return nil, err
		}
		if closed != nil {
			return nil, closed
		}
		if err = syncParent(path); err != nil {
			return nil, err
		}
	} else if !os.IsExist(err) {
		return nil, err
	}
	if err = executorPrivateKeyFile(path); err != nil {
		return nil, err
	}
	private, err := readBoundedFile(path, ed25519.PrivateKeySize)
	if err != nil {
		return nil, err
	}
	if len(private) != ed25519.PrivateKeySize || !bytes.Equal(private, ed25519.NewKeyFromSeed(private[:ed25519.SeedSize])) {
		return nil, errors.New("invalid executor result signing key; operator recovery required")
	}
	return ed25519.PrivateKey(private), nil
}
func executorPublicKey(c Config) (string, error) {
	if err := executorTrustedConfig(os.Getenv("AGENT_CONFIG")); err != nil {
		return "", err
	}
	if err := executorPlatform(); err != nil {
		return "", err
	}
	if !filepath.IsAbs(c.StateDir) {
		return "", errors.New("executor private state path required")
	}
	if err := executorTrustedDirectory(filepath.Dir(c.StateDir), false); err != nil {
		return "", err
	}
	if err := os.MkdirAll(c.StateDir, 0700); err != nil {
		return "", err
	}
	if err := executorTrustedDirectory(c.StateDir, true); err != nil {
		return "", err
	}
	// Public-key export must not run startup upgrade recovery or alter receipts.
	key, err := executorResultKey(c.StateDir)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(key.Public().(ed25519.PublicKey)), nil
}
func (e *privilegedExecutor) process(auth TaskAuthorization) Result {
	result := e.processAuthorized(auth)
	raw, err := base64.StdEncoding.DecodeString(auth.Payload)
	if err != nil || len(raw) > 64<<10 {
		return result
	}
	signature, err := base64.StdEncoding.DecodeString(auth.Signature)
	if err != nil || !ed25519.Verify(e.key, raw, signature) {
		return result
	}
	var task executorPayload
	if json.Unmarshal(raw, &task) != nil || task.ID == "" || task.AssetID != e.assetID {
		return result
	}
	details := map[string]string{"executorVersion": agentVersion}
	for key, value := range result.Details {
		if key != "executorProof" {
			details[key] = value
		}
	}
	body := struct {
		TaskID  string `json:"taskId"`
		AssetID string `json:"assetId"`
		Result  struct {
			Success  bool              `json:"success"`
			Evidence string            `json:"evidence"`
			Details  map[string]string `json:"details"`
		} `json:"result"`
	}{TaskID: task.ID, AssetID: e.assetID}
	body.Result.Success = result.Success
	body.Result.Evidence = result.Evidence
	body.Result.Details = details
	payload, err := json.Marshal(body)
	if err != nil {
		return Result{Evidence: "executor result proof encoding failed", Details: map[string]string{"resultUnknown": "true"}}
	}
	proof, err := json.Marshal(TaskAuthorization{Payload: base64.StdEncoding.EncodeToString(payload), Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(e.resultKey, payload))})
	if err != nil {
		return Result{Evidence: "executor result proof encoding failed", Details: map[string]string{"resultUnknown": "true"}}
	}
	returned := map[string]string{}
	for key, value := range details {
		returned[key] = value
	}
	returned["executorProof"] = string(proof)
	result.Details = returned
	return result
}
