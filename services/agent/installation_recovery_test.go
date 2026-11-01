package main

import (
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

func TestInstallationRecoveryKeepsAcceptedOrUncertainPrograms(t *testing.T) {
	state := "/var/lib/selfguard-agent-recovery-test-" + strconv.Itoa(os.Getpid())
	if err := os.Mkdir(state, 0700); err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(state)
	if err := writePrivate(filepath.Join(state, "identity.json"), Identity{Token: "bound-recovery-component"}); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer bound-recovery-component" || r.URL.Path != "/api/agent/install/fixture/recovery" {
			t.Error("recovery not bound to its component and installation")
		}
		var body struct {
			Phase string `json:"phase"`
		}
		json.NewDecoder(r.Body).Decode(&body)
		if body.Phase != "PREPARE" {
			t.Error("accepted install should not be reported recovered")
		}
		w.Write([]byte(`{"accepted":true,"status":"SUCCEEDED"}`))
	}))
	defer server.Close()
	config := Config{Server: server.URL, CACertificate: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})), StateDir: state}
	for _, uncertain := range []bool{false, true} {
		root := t.TempDir()
		file := filepath.Join(root, "current")
		os.WriteFile(file, []byte("before"), 0755)
		tx, err := beginInstallationTransaction(filepath.Join(root, "transactions"), "fixture", []string{file})
		if err != nil {
			t.Fatal(err)
		}
		tx.write(file, []byte("running candidate"), 0755)
		tx.InstallationID = "fixture"
		tx.Connection = config
		tx.AcceptanceAttempted = true
		if uncertain {
			tx.Connection.Server = "https://127.0.0.1:1"
		}
		accepted, err := tx.recoverInstallation()
		if uncertain {
			if err == nil || accepted || tx.Status != "RECOVERY_REQUIRED" {
				t.Fatal("uncertain acceptance allowed rollback", accepted, err)
			}
		} else if err != nil || !accepted || tx.Status != "COMMITTED" {
			t.Fatal("accepted installation was not retained", accepted, err)
		}
		body, _ := os.ReadFile(file)
		if string(body) != "running candidate" {
			t.Fatal("accepted or uncertain program overwritten")
		}
	}
}
