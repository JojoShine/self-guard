package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"
)

func databaseQueueKey(path string, create bool) ([]byte, error) {
	keyPath := filepath.Join(filepath.Dir(path), "database-queue.key")
	info, err := os.Lstat(keyPath)
	if os.IsNotExist(err) && create {
		key := make([]byte, 32)
		if _, err = rand.Read(key); err != nil {
			return nil, err
		}
		f, e := os.OpenFile(keyPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if e != nil {
			return nil, e
		}
		_, err = f.Write(key)
		if err == nil {
			err = f.Sync()
		}
		closeErr := f.Close()
		if err != nil {
			return nil, err
		}
		if closeErr != nil {
			return nil, closeErr
		}
		if err = syncParent(keyPath); err != nil {
			return nil, err
		}
		info, err = os.Lstat(keyPath)
	}
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("database queue key must be a private regular file")
	}
	key, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}
	if len(key) != 32 {
		return nil, errors.New("database queue key invalid")
	}
	return key, nil
}
func databaseQueueCipher(path string, create bool) (cipher.AEAD, error) {
	key, err := databaseQueueKey(path, create)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
func sealDatabaseQueue(path string, body []byte) ([]byte, error) {
	aead, err := databaseQueueCipher(path, true)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return nil, err
	}
	encrypted := aead.Seal(nonce, nonce, body, []byte("selfguard-database-queue-v1"))
	return json.Marshal(map[string]string{"encryptedDatabaseQueue": base64.StdEncoding.EncodeToString(encrypted)})
}
func openDatabaseQueue(path string, body []byte) ([]byte, error) {
	// Existing metadata queues remain readable during an in-place collector upgrade.
	var envelope struct {
		Encrypted string `json:"encryptedDatabaseQueue"`
	}
	if string(body) == "null" || (len(body) > 0 && body[0] == '[') {
		return body, nil
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, err
	}
	if envelope.Encrypted == "" {
		return nil, errors.New("invalid database queue envelope")
	}
	raw, err := base64.StdEncoding.DecodeString(envelope.Encrypted)
	if err != nil {
		return nil, err
	}
	aead, err := databaseQueueCipher(path, false)
	if err != nil {
		return nil, err
	}
	if len(raw) < aead.NonceSize()+aead.Overhead() {
		return nil, errors.New("invalid encrypted database queue")
	}
	return aead.Open(nil, raw[:aead.NonceSize()], raw[aead.NonceSize():], []byte("selfguard-database-queue-v1"))
}

// Retain the audit metadata for delivery, but expire SQL even while the platform is offline.
func (a *Agent) expireDatabaseSQL() error {
	changed := false
	next := append([]Pending{}, a.DatabaseQueue...)
	cutoff := time.Now().Add(-7 * 24 * time.Hour)
	for i, pending := range next {
		var body struct {
			Events []map[string]json.RawMessage `json:"events"`
		}
		if err := json.Unmarshal(pending.Body, &body); err != nil {
			return err
		}
		dirty := false
		for _, event := range body.Events {
			var timestamp string
			if json.Unmarshal(event["timestamp"], &timestamp) != nil {
				continue
			}
			at, err := time.Parse(time.RFC3339Nano, timestamp)
			if err != nil || at.After(cutoff) {
				continue
			}
			var execution map[string]json.RawMessage
			if json.Unmarshal(event["execution"], &execution) != nil {
				continue
			}
			if _, ok := execution["sql"]; !ok {
				continue
			}
			delete(execution, "sql")
			raw, err := json.Marshal(execution)
			if err != nil {
				return err
			}
			event["execution"] = raw
			dirty = true
		}
		if dirty {
			raw, err := json.Marshal(body)
			if err != nil {
				return err
			}
			next[i].Body = raw
			changed = true
		}
	}
	if changed {
		if err := writePrivate(filepath.Join(a.Config.StateDir, "database-queue.json"), next); err != nil {
			return err
		}
		a.DatabaseQueue = next
	}
	return nil
}
