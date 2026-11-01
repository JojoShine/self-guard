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
	"syscall"
	"testing"
	"time"
)

func TestInstallationExecutableDirectoryIsTraversableWithPrivateBootstrapUmask(t *testing.T) {
	mask := syscall.Umask(0077)
	defer syscall.Umask(mask)
	root := filepath.Join(t.TempDir(), "installation")
	if err := installManagedBinary(root, []byte("signed executable"), 1); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(root)
	if err != nil || info.Mode().Perm() != 0755 {
		t.Fatalf("collector cannot traverse binary directory: %v %v", info, err)
	}
}

func TestInstallationSignatureAndIdentityPersistence(t *testing.T) {
	pub, private, _ := ed25519.GenerateKey(rand.Reader)
	candidate := []byte("agent executable fixture")
	sum := sha256.Sum256(candidate)
	manifest := UpgradeManifest{Version: "1.0.0", Sequence: 3, SHA256: hex.EncodeToString(sum[:]), Size: int64(len(candidate)), OS: "linux", Architecture: runtime.GOARCH, ExpiresAt: time.Now().Add(time.Hour)}
	raw, _ := json.Marshal(manifest)
	envelope := installationRelease{ManifestBytes: base64.StdEncoding.EncodeToString(raw), Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(private, raw))}
	root := base64.StdEncoding.EncodeToString(pub)
	if _, err := verifyInstallationRelease(envelope, root, candidate, "linux", runtime.GOARCH, 0); err != nil {
		t.Fatal(err)
	}
	for _, x := range []struct {
		bytes    []byte
		arch     string
		sequence uint64
	}{{[]byte("corrupt"), runtime.GOARCH, 0}, {candidate, "wrong", 0}, {candidate, runtime.GOARCH, 4}} {
		if _, err := verifyInstallationRelease(envelope, root, x.bytes, "linux", x.arch, x.sequence); err == nil {
			t.Fatal("unsafe installation accepted")
		}
	}
	dir := t.TempDir()
	first, err := installationIdentity(dir)
	if err != nil {
		t.Fatal(err)
	}
	again, err := installationIdentity(dir)
	if err != nil || first.Identity != again.Identity || first.EnrollmentSecret != again.EnrollmentSecret {
		t.Fatal("retry changed identity")
	}
	info, _ := os.Stat(filepath.Join(dir, "identity.json"))
	if info.Mode().Perm() != 0600 {
		t.Fatal("identity permissions")
	}
}
func TestInstallationUnitsSeparateCollectorAndExecutor(t *testing.T) {
	collector := installationCollectorUnit(false)
	if strings.Contains(collector, "Requires=selfguard-executor") || !strings.Contains(collector, "User=selfguard-agent") {
		t.Fatal(collector)
	}
	if !strings.Contains(installationCollectorUnit(true), "Requires=selfguard-executor.service") {
		t.Fatal("missing explicit executor dependency")
	}
	executor := installationExecutorUnit("/srv/managed")
	if !strings.Contains(executor, "User=root") || !strings.Contains(executor, "/srv/managed") {
		t.Fatal(executor)
	}
}
func TestInstallationPathPreflightRefusesUnknownExistingFilesAndPreservesState(t *testing.T) {
	root := t.TempDir()
	candidate := []byte("verified agent")
	if err := installManagedBinary(root, candidate, 3); err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(root, "identity.json")
	_ = os.WriteFile(state, []byte("keep"), 0600)
	if err := installManagedBinary(root, candidate, 3); err != nil {
		t.Fatal(err)
	}
	if err := installManagedBinary(root, []byte("changed"), 3); err == nil {
		t.Fatal("same sequence overwrite accepted")
	}
	if err := installManagedBinary(root, candidate, 2); err == nil {
		t.Fatal("downgrade accepted")
	}
	b, _ := os.ReadFile(state)
	if string(b) != "keep" {
		t.Fatal("state removed")
	}
	other := t.TempDir()
	_ = os.WriteFile(filepath.Join(other, "current"), []byte("administrator file"), 0755)
	if err := installManagedBinary(other, candidate, 4); err == nil {
		t.Fatal("unmanaged executable overwritten")
	}
}

func TestOfflinePreparationDoesNotClaimOnlineSuccess(t *testing.T) {
	p := installationProfile{Server: "https://guard.example"}
	state, err := offlineInstallationState(p, "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	if state["status"] != "LOCAL_ONLY" || state["platformVerified"] != false {
		t.Fatal(state)
	}
	for _, server := range []string{"ftp://guard.example", "https://user:secret@guard.example", "https://guard.example/api"} {
		if _, err := offlineInstallationState(installationProfile{Server: server}, "1.0.0"); err == nil {
			t.Fatal("invalid offline server accepted")
		}
	}
}
func TestInstallationResumesAfterVerifiedUpgradeWithoutOverwritingUnknownBytes(t *testing.T) {
	root := t.TempDir()
	if err := installManagedBinary(root, []byte("initial signed binary"), 1); err != nil {
		t.Fatal(err)
	}
	// The privileged upgrade path has already replaced current. A repeated
	// installation must accept only the exact newly verified candidate bytes.
	candidate := []byte("new signed binary")
	if err := os.WriteFile(filepath.Join(root, "current"), candidate, 0755); err != nil {
		t.Fatal(err)
	}
	if err := installManagedBinary(root, candidate, 2); err != nil {
		t.Fatal(err)
	}
	var slot installationSlot
	if err := read(filepath.Join(root, "installation-slot.json"), &slot); err != nil || slot.Sequence != 2 {
		t.Fatal("upgraded receipt not reconciled", err)
	}
	if err := os.WriteFile(filepath.Join(root, "current"), []byte("unknown executable"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := installManagedBinary(root, []byte("next signed binary"), 3); err == nil {
		t.Fatal("unknown existing executable replaced")
	}
}
func TestManagedConfigurationRefusesSilentAdministratorOverwrite(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "collector.json")
	if err := writeInstallationManagedFile(file, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := writeInstallationManagedFile(file, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte("local administrator change"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := writeInstallationManagedFile(file, []byte("replacement"), 0600); err == nil {
		t.Fatal("administrator change overwritten")
	}
	unknown := filepath.Join(root, "unknown.json")
	_ = os.WriteFile(unknown, []byte("manual config"), 0600)
	if err := writeInstallationManagedFile(unknown, []byte("replacement"), 0600); err == nil {
		t.Fatal("unmanaged file overwritten")
	}
}

func TestInstallationClaimRecoversLostResponseWithPersistedSecret(t *testing.T) {
	identity := Identity{Identity: "persistent-host", EnrollmentSecret: strings.Repeat("A", 43)}
	requests := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		switch r.Header.Get("Authorization") {
		case "Bearer " + strings.Repeat("B", 43):
			w.Header().Set("Content-Length", "100")
			w.Write([]byte(`{"assetId":`))
		case "Bearer " + identity.EnrollmentSecret:
			json.NewEncoder(w).Encode(installationClaim{AssetID: "same-asset", Token: identity.EnrollmentSecret})
		default:
			w.WriteHeader(401)
		}
	}))
	defer server.Close()
	var claim installationClaim
	if err := claimInstallation(server.Client(), server.URL, "task-id", strings.Repeat("B", 43), identity, "host", &claim); err != nil {
		t.Fatal(err)
	}
	if requests != 2 || claim.AssetID != "same-asset" || claim.Token != identity.EnrollmentSecret {
		t.Fatal("lost response recovery changed persisted identity")
	}
}

func TestInstallationAfterManagedUpgradeCanAdvanceToAnotherRelease(t *testing.T) {
	root := t.TempDir()
	installManagedBinary(root, []byte("initial"), 1)
	current := []byte("verified upgrade")
	os.WriteFile(filepath.Join(root, "current"), current, 0755)
	digest := sha256.Sum256(current)
	installed := UpgradeManifest{Version: "0.2.0", Sequence: 2, SHA256: hex.EncodeToString(digest[:]), Size: int64(len(current)), OS: runtime.GOOS, Architecture: runtime.GOARCH, ExpiresAt: time.Now().Add(time.Hour)}
	writePrivate(filepath.Join(root, "installed.json"), installed)
	writePrivate(filepath.Join(root, "highest-sequence.json"), installed)
	next := []byte("later signed installer")
	if err := preflightInstallationFiles(root, next, 3, nil); err != nil {
		t.Fatal("verified upgrade metadata did not reconcile old installer slot", err)
	}
	if err := installManagedBinary(root, next, 3); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(root, "current"), []byte("unknown modification"), 0755)
	if err := preflightInstallationFiles(root, []byte("next"), 4, nil); err == nil {
		t.Fatal("trusted metadata accepted different bytes")
	}
}
