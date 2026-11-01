package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type installationRelease struct {
	ManifestBytes string `json:"manifestBytes"`
	Signature     string `json:"signature"`
}
type installationProfile struct {
	HostWaf *struct {
		SiteID string `json:"siteId"`
	} `json:"hostWaf"`
	ApplicationInputs []ApplicationInput `json:"applicationInputs"`
	ProxyMode         string             `json:"proxyMode"`
	StateDir          string             `json:"stateDir"`
	ProxyURL          string             `json:"proxyUrl"`
	CollectionRoot    string             `json:"collectionRoot"`
	FIMPaths          []string           `json:"fimPaths"`
	LogPaths          []string           `json:"logPaths"`
	LogIncludeMessage bool               `json:"logIncludeMessage"`
	MaxCPUs           int                `json:"maxCPUs"`
	MaxMemoryBytes    int64              `json:"maxMemoryBytes"`
	MaxQueueBytes     int64              `json:"maxQueueBytes"`
	BytesPerSecond    int64              `json:"bytesPerSecond"`
	CPUQuotaPercent   int                `json:"cpuQuotaPercent"`
	Server            string             `json:"server"`
	ExecutorEnabled   bool               `json:"executorEnabled"`
	AllowedRoot       string             `json:"allowedRoot"`
	AllowedServices   []string           `json:"allowedServices"`
	CACertificate     string             `json:"caCertificate"`
}
type installationClaim struct {
	AssetID       string              `json:"assetId"`
	Token         string              `json:"token"`
	Profile       installationProfile `json:"profile"`
	Release       installationRelease `json:"release"`
	Challenge     string              `json:"challenge"`
	TaskPublicKey string              `json:"taskPublicKey"`
}

func verifyInstallationRelease(release installationRelease, root string, candidate []byte, osName, arch string, highest uint64) (UpgradeManifest, error) {
	var m UpgradeManifest
	raw, err := base64.StdEncoding.DecodeString(release.ManifestBytes)
	if err != nil {
		return m, errors.New("invalid release envelope")
	}
	sig, err := base64.StdEncoding.DecodeString(release.Signature)
	if err != nil {
		return m, errors.New("invalid release signature")
	}
	pub, err := base64.StdEncoding.DecodeString(root)
	if err != nil || len(pub) != ed25519.PublicKeySize || !ed25519.Verify(ed25519.PublicKey(pub), raw, sig) {
		return m, errors.New("untrusted release signature")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&m); err != nil {
		return m, err
	}
	sum := sha256.Sum256(candidate)
	if m.Version == "" || m.Sequence == 0 || m.Sequence < highest || m.SHA256 != hex.EncodeToString(sum[:]) || m.Size != int64(len(candidate)) || m.Size < 1 || m.Size > 64<<20 || m.OS != osName || m.Architecture != arch || !m.ExpiresAt.After(time.Now()) {
		return m, errors.New("release target, checksum, sequence or expiry mismatch")
	}
	return m, nil
}
func installationIdentity(dir string) (Identity, error) {
	var identity Identity
	if err := os.MkdirAll(dir, 0700); err != nil {
		return identity, err
	}
	if err := safePath(dir, dir); err != nil {
		return identity, err
	}
	path := filepath.Join(dir, "identity.json")
	if _, err := os.Lstat(path); err == nil {
		if err = safePath(dir, path); err != nil {
			return identity, err
		}
		info, _ := os.Lstat(path)
		if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || multipleLinks(info) {
			return identity, errors.New("untrusted persisted identity")
		}
		if err = read(path, &identity); err != nil {
			return identity, err
		}
		if identity.Identity == "" || len(identity.EnrollmentSecret) < 32 {
			return identity, errors.New("existing identity incomplete; explicit recovery required")
		}
		return identity, nil
	} else if !os.IsNotExist(err) {
		return identity, err
	}
	b := make([]byte, 64)
	if _, err := rand.Read(b); err != nil {
		return identity, err
	}
	identity.Identity = "sg-" + hex.EncodeToString(b[:16])
	identity.EnrollmentSecret = base64.RawURLEncoding.EncodeToString(b[16:48])
	return identity, writePrivate(path, identity)
}

type installationSlot struct {
	SHA256   string
	Sequence uint64
}

func writeInstallationSlot(root string, slot installationSlot, transactions ...*installationTransaction) error {
	if err := installationPrivate(filepath.Join(root, "installation-slot.json"), slot, transactions...); err != nil {
		return err
	}
	// The bootstrap uses umask 077. Only the managed executable directory is
	// traversable; identity, keys and receipts keep their private file modes.
	return os.Chmod(root, 0755)
}

func installManagedBinary(root string, candidate []byte, sequence uint64, transactions ...*installationTransaction) error {
	if err := os.MkdirAll(root, 0755); err != nil {
		return err
	}
	if err := safePath(root, root); err != nil {
		return err
	}
	current := filepath.Join(root, "current")
	marker := filepath.Join(root, "installation-slot.json")
	var old installationSlot
	if err := read(marker, &old); err != nil {
		return err
	}
	sum := sha256.Sum256(candidate)
	digest := hex.EncodeToString(sum[:])
	if old.Sequence > sequence || old.Sequence == sequence && old.SHA256 != digest {
		return errors.New("installation replay or same-sequence content change refused")
	}
	if _, err := os.Lstat(current); err == nil {
		if old.Sequence == 0 {
			return errors.New("existing executable is not managed by this installer")
		}
		before, err := readBoundedFile(current, 64<<20)
		if err != nil {
			return err
		}
		actual := sha256.Sum256(before)
		if hex.EncodeToString(actual[:]) == digest {
			return writeInstallationSlot(root, installationSlot{SHA256: digest, Sequence: sequence}, transactions...)
		}
		if hex.EncodeToString(actual[:]) != old.SHA256 && !trustedInstalledExecutable(root, hex.EncodeToString(actual[:]), old.Sequence, int64(len(before))) {
			return errors.New("existing executable changed; operator recovery required")
		}
		if err = installationWrite(filepath.Join(root, "current.install-backup"), before, 0755, transactions...); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := installationWrite(current, candidate, 0755, transactions...); err != nil {
		return err
	}
	return writeInstallationSlot(root, installationSlot{SHA256: digest, Sequence: sequence}, transactions...)
}
func installationCollectorUnit(executor bool, profiles ...Config) string {
	dependency := ""
	if executor {
		dependency = "After=selfguard-executor.service\nRequires=selfguard-executor.service\n"
	}
	unit := "[Unit]\nDescription=Self Guard unprivileged collector\nAfter=network-online.target\nWants=network-online.target\n" + dependency + `[Service]
Type=simple
User=selfguard-agent
Group=selfguard-agent
ExecStart=/opt/selfguard-agent/current
Environment=AGENT_CONFIG=/etc/selfguard-agent/collector.json
Restart=on-failure
RestartSec=10
StateDirectory=selfguard-agent
StateDirectoryMode=0700
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
ReadWritePaths=/var/lib/selfguard-agent
CPUQuota=20%
MemoryMax=128M
TasksMax=64
[Install]
WantedBy=multi-user.target
`
	if len(profiles) > 0 {
		c := profiles[0]
		unit = strings.ReplaceAll(unit, "StateDirectory=selfguard-agent\n", "StateDirectory="+filepath.Base(c.StateDir)+"\n")
		unit = strings.ReplaceAll(unit, "ReadWritePaths=/var/lib/selfguard-agent\n", "ReadWritePaths="+c.StateDir+"\n")
		if c.MaxMemoryBytes > 0 {
			unit = strings.ReplaceAll(unit, "MemoryMax=128M", "MemoryMax="+strconv.FormatInt(c.MaxMemoryBytes, 10))
		}
		if c.CPUQuotaPercent > 0 {
			unit = strings.ReplaceAll(unit, "CPUQuota=20%", "CPUQuota="+strconv.Itoa(c.CPUQuotaPercent)+"%")
		}
	}
	return unit
}
func installationExecutorUnit(allowedRoot string) string {
	return `[Unit]
Description=Self Guard privileged signed executor
After=local-fs.target
[Service]
Type=simple
User=root
Group=selfguard-agent
ExecStart=/opt/selfguard-agent/current --executor
Environment=AGENT_CONFIG=/etc/selfguard-agent/executor.json
Restart=on-failure
RestartSec=10
RuntimeDirectory=selfguard-executor
RuntimeDirectoryMode=0750
StateDirectory=selfguard-executor
StateDirectoryMode=0700
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
ReadWritePaths=/run/selfguard-executor /var/lib/selfguard-executor /opt/selfguard-agent ` + allowedRoot + `
MemoryMax=128M
TasksMax=32
[Install]
WantedBy=multi-user.target
`
}
func installationAccount() (int, int, error) {
	if err := trustedInstallCommand("id", "-u", "selfguard-agent"); err != nil {
		manager, detectErr := currentInstallationInit()
		if detectErr != nil {
			return 0, 0, detectErr
		}
		if manager == "openrc" {
			if trustedInstallCommand("getent", "group", "selfguard-agent") != nil {
				if err = trustedInstallCommand("addgroup", "-S", "selfguard-agent"); err != nil {
					return 0, 0, err
				}
			}
			err = trustedInstallCommand("adduser", "-S", "-D", "-H", "-h", "/var/lib/selfguard-agent", "-s", "/sbin/nologin", "-G", "selfguard-agent", "selfguard-agent")
		} else {
			err = trustedInstallCommand("useradd", "--system", "--user-group", "--home-dir", "/var/lib/selfguard-agent", "--shell", "/usr/sbin/nologin", "selfguard-agent")
		}
		if err != nil {
			return 0, 0, err
		}
	}
	account, err := user.Lookup("selfguard-agent")
	if err != nil {
		return 0, 0, err
	}
	uid, err := strconv.Atoi(account.Uid)
	if err != nil || uid == 0 {
		return 0, 0, errors.New("collector account must be unprivileged")
	}
	gid, err := strconv.Atoi(account.Gid)
	return uid, gid, err
}
func installationCollectorConfig(server, root, ca string) Config {
	return Config{Server: server, AllowHTTP: strings.HasPrefix(server, "http://"), StateDir: "/var/lib/selfguard-agent", MaxCPUs: 1, MaxMemoryBytes: 128 << 20, MaxQueueBytes: 32 << 20, BytesPerSecond: 128 << 10, UpgradePublicKey: root, UpgradeInstallRoot: "/opt/selfguard-agent", UpgradeOrigins: []string{strings.TrimSuffix(server, "/")}, CACertificate: ca}
}
func protectCollectorFiles(state string, uid, gid int) error {
	if err := os.Chown("/etc/selfguard-agent", 0, gid); err != nil {
		return err
	}
	if err := os.Chmod("/etc/selfguard-agent", 0750); err != nil {
		return err
	}
	if err := os.Chown("/etc/selfguard-agent/collector.json", 0, gid); err != nil {
		return err
	}
	if err := os.Chmod("/etc/selfguard-agent/collector.json", 0640); err != nil {
		return err
	}
	if err := os.Chown(state, uid, gid); err != nil {
		return err
	}
	return os.Chown(filepath.Join(state, "identity.json"), uid, gid)
}
func installationLock() (func(), error) {
	root := "/opt/selfguard-agent"
	if err := os.MkdirAll(root, 0755); err != nil {
		return nil, err
	}
	if err := executorTrustedDirectory(root, false); err != nil {
		return nil, err
	}
	return lockInstallationFile(filepath.Join(root, "operation.lock"))
}
func lockInstallationFile(path string) (func(), error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, err
	}
	if err = executorTrustedConfig(path); err != nil {
		file.Close()
		return nil, err
	}
	if err = syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		file.Close()
		return nil, fmt.Errorf("another installation or recovery is active: %w", err)
	}
	return func() { _ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN); _ = file.Close() }, nil
}
func completeOfflineReceipt(assetID, version string, executorEnabled bool) error {
	path := "/opt/selfguard-agent/offline-installation.json"
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return err
	}
	var receipt map[string]any
	if err := read(path, &receipt); err != nil {
		return err
	}
	if receipt == nil {
		return errors.New("offline receipt is incomplete")
	}
	receipt["status"] = "PLATFORM_VERIFIED"
	receipt["platformVerified"] = true
	receipt["assetId"] = assetID
	receipt["version"] = version
	receipt["executorPending"] = false
	receipt["executorEnabled"] = executorEnabled
	receipt["verifiedAt"] = time.Now().UTC()
	return writePrivate(path, receipt)
}
func trustedInstallCommand(name string, args ...string) error {
	var path string
	for _, dir := range []string{"/usr/sbin", "/usr/bin", "/sbin", "/bin"} {
		p := filepath.Join(dir, name)
		if info, err := os.Stat(p); err == nil && info.Mode().IsRegular() {
			path = p
			break
		}
	}
	if path == "" {
		return fmt.Errorf("required system tool unavailable: %s", name)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C"}
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("system operation failed: %s %s: %w", name, strings.Join(args, " "), err)
	}
	return nil
}
func installationClient(ca string, proxies ...string) (*http.Client, error) {
	roots, err := x509.SystemCertPool()
	if err != nil {
		roots = x509.NewCertPool()
	}
	if ca != "" && !roots.AppendCertsFromPEM([]byte(ca)) {
		return nil, errors.New("invalid CA certificate")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if len(proxies) > 0 {
		transport.Proxy = nil
	}
	if len(proxies) > 0 && proxies[0] != "" {
		proxy, e := installationProxy(proxies[0])
		if e != nil {
			return nil, e
		}
		transport.Proxy = http.ProxyURL(proxy)
	}
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}
	return &http.Client{Transport: transport, Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, nil
}
func installationRequest(client *http.Client, server, id, action, secret string, body any, out any) error {
	raw, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequest("POST", strings.TrimSuffix(server, "/")+"/api/agent/install/"+id+"/"+action, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+secret)
	response, err := client.Do(req)
	if err != nil {
		return errors.New("installation platform connection failed")
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("installation platform rejected %s (%d)", action, response.StatusCode)
	}
	if out != nil {
		return json.NewDecoder(io.LimitReader(response.Body, 2<<20)).Decode(out)
	}
	return nil
}
func claimInstallation(client *http.Client, server, id, ticket string, identity Identity, host string, claim *installationClaim) error {
	body := map[string]string{"identity": identity.Identity, "credential": identity.EnrollmentSecret, "hostname": host, "architecture": runtime.GOARCH}
	err := installationRequest(client, server, id, "claim", ticket, body, claim)
	if err == nil {
		return nil
	}
	// The secret is persisted before the first request. It recovers a consumed
	// ticket even when the successful registration response was lost.
	if len(identity.EnrollmentSecret) < 32 || ticket == identity.EnrollmentSecret {
		return err
	}
	return installationRequest(client, server, id, "claim", identity.EnrollmentSecret, body, claim)
}
func runInstallation(server, id, root string, input io.Reader, output io.Writer) (resultErr error) {
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		return errors.New("installation requires Linux root")
	}
	u, err := url.Parse(server)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || !validPlatformPath(u) {
		return errors.New("HTTP or HTTPS platform origin required")
	}
	if len(id) != 36 || strings.ContainsAny(id, "/\\\r\n") {
		return errors.New("invalid installation task ID")
	}
	if err = requireInstallationHost(); err != nil {
		return err
	}
	unlock, err := installationLock()
	if err != nil {
		return err
	}
	defer unlock()
	if err = unfinishedInstallationTransactions(); err != nil {
		return err
	}
	scanner := bufio.NewScanner(io.LimitReader(input, 4096))
	if !scanner.Scan() {
		return errors.New("installation ticket must be supplied on stdin")
	}
	ticket := strings.TrimSpace(scanner.Text())
	if len(ticket) < 32 {
		return errors.New("installation ticket missing")
	}
	ca := ""
	if path := os.Getenv("AGENT_CA_FILE"); path != "" {
		b, e := readBoundedFile(path, 32000)
		if e != nil {
			return e
		}
		ca = string(b)
	}
	client, err := clientForConfig(Config{CACertificate: ca, ProxyURL: os.Getenv("AGENT_PROXY_URL"), ProxyMode: os.Getenv("AGENT_PROXY_MODE")})
	if err != nil {
		return err
	}
	uid, gid, err := installationAccount()
	if err != nil {
		return err
	}
	state, err := installationStateDir(os.Getenv("AGENT_INSTALL_STATE_DIR"))
	if err != nil {
		return err
	}
	if err = existingInstallationState(state); err != nil {
		return err
	}
	identity, err := installationIdentity(state)
	if err != nil {
		return err
	}
	host, _ := os.Hostname()
	var claim installationClaim
	if err = claimInstallation(client, server, id, ticket, identity, host, &claim); err != nil {
		return err
	}
	identity.AssetID = claim.AssetID
	identity.Token = claim.Token
	transactionStarted := false
	defer func() {
		if resultErr != nil && !transactionStarted {
			_ = installationRequest(client, server, id, "report", identity.Token, map[string]string{"status": "FAILED", "version": agentVersion}, nil)
		}
	}()
	candidate, err := os.ReadFile("/proc/self/exe")
	if err != nil {
		return err
	}
	var highest UpgradeManifest
	if err = read("/opt/selfguard-agent/highest-sequence.json", &highest); err != nil {
		return err
	}
	manifest, err := verifyInstallationRelease(claim.Release, root, candidate, "linux", runtime.GOARCH, highest.Sequence)
	if err != nil {
		return err
	}
	if manifest.Version != agentVersion {
		return errors.New("executable build version differs from signed manifest")
	}
	if claim.Profile.Server != server && strings.TrimSuffix(claim.Profile.Server, "/") != strings.TrimSuffix(server, "/") {
		return errors.New("installation profile origin mismatch")
	}
	if err = writePrivate(filepath.Join(state, "identity.json"), identity); err != nil {
		return err
	}
	if err = os.MkdirAll("/etc/selfguard-agent", 0750); err != nil {
		return err
	}
	if err = executorTrustedDirectory("/etc/selfguard-agent", false); err != nil {
		return err
	}
	config, err := applyInstallationProfile(installationCollectorConfig(server, root, ca), claim.Profile)
	if err != nil {
		return err
	}
	if config.StateDir != state || config.ProxyURL != os.Getenv("AGENT_PROXY_URL") || os.Getenv("AGENT_PROXY_MODE") != "" && config.ProxyMode != os.Getenv("AGENT_PROXY_MODE") {
		return errors.New("bootstrap configuration differs from authorized installation profile")
	}
	if err = preflightInstallationFiles("/opt/selfguard-agent", candidate, manifest.Sequence, managedInstallationConfigFiles()); err != nil {
		return err
	}
	tx, err := beginInstallationTransaction("/opt/selfguard-agent/install-transactions", id+"-"+strconv.FormatInt(time.Now().UnixNano(), 10), installationManagedPaths())
	if err != nil {
		return err
	}
	transactionStarted = true
	tx.InstallationID = id
	tx.Version = agentVersion
	tx.Connection = Config{Server: config.Server, AllowHTTP: config.AllowHTTP, CACertificate: ca, ProxyURL: config.ProxyURL, ProxyMode: config.ProxyMode, StateDir: config.StateDir}
	keepLocal := false
	defer func() {
		if resultErr != nil && tx.Status == "OPEN" && !keepLocal {
			_, recoveryErr := tx.recoverInstallation()
			resultErr = errors.Join(resultErr, recoveryErr)
		}
	}()
	if err = tx.captureServices(); err != nil {
		return err
	}
	if err = installManagedBinary("/opt/selfguard-agent", candidate, manifest.Sequence, tx); err != nil {
		return err
	}
	if err = tx.writePrivate("/opt/selfguard-agent/installed.json", manifest); err != nil {
		return err
	}
	if err = writePrivate("/opt/selfguard-agent/highest-sequence.json", manifest); err != nil {
		return err
	}
	if claim.Profile.ExecutorEnabled {
		allowed := claim.Profile.AllowedRoot
		if allowed == "/" || strings.ContainsAny(allowed, " \t\r\n%\"\\") || strings.Contains(allowed, "..") {
			return errors.New("invalid managed directory")
		}
		if err = executorTrustedDirectory(allowed, false); err != nil {
			return err
		}
		key, err := base64.StdEncoding.DecodeString(claim.TaskPublicKey)
		if err != nil || len(key) != 32 {
			return errors.New("task verification key unavailable")
		}
		executorState := "/var/lib/selfguard-executor"
		if err = os.MkdirAll(executorState, 0700); err != nil {
			return err
		}
		if err = executorTrustedDirectory(executorState, true); err != nil {
			return err
		}
		publicUID := uint32(uid)
		executorConfig := Config{Server: server, AllowHTTP: config.AllowHTTP, StateDir: executorState, ExecutorSocket: "/run/selfguard-executor/executor.sock", ExecutorPublicKey: claim.TaskPublicKey, ExecutorAssetID: claim.AssetID, ExecutorAllowedUID: &publicUID, AllowedRoot: allowed, AllowedServices: claim.Profile.AllowedServices, UpgradePublicKey: root, UpgradeInstallRoot: "/opt/selfguard-agent", UpgradeOrigins: config.UpgradeOrigins, CACertificate: ca, ProxyURL: config.ProxyURL, ProxyMode: config.ProxyMode}
		if err = writeInstallationConfig("/etc/selfguard-agent/executor.json", executorConfig, tx); err != nil {
			return err
		}
		private, err := executorResultKey(executorState)
		if err != nil {
			return err
		}
		message := []byte("selfguard-install-v1\n" + id + "\n" + claim.AssetID + "\n" + claim.Challenge)
		if err = installationRequest(client, server, id, "executor", identity.Token, map[string]string{"publicKey": base64.StdEncoding.EncodeToString(private.Public().(ed25519.PublicKey)), "signature": base64.StdEncoding.EncodeToString(ed25519.Sign(private, message))}, nil); err != nil {
			return err
		}
		if err = writeInstallationService("selfguard-executor.service", true, executorConfig, tx); err != nil {
			return err
		}
		config.ExecutorSocket = executorConfig.ExecutorSocket
	}
	if err = writeInstallationConfig("/etc/selfguard-agent/collector.json", config, tx); err != nil {
		return err
	}
	if err = protectCollectorFiles(state, uid, gid); err != nil {
		return err
	}
	if err = writeInstallationService("selfguard-collector.service", claim.Profile.ExecutorEnabled, config, tx); err != nil {
		return err
	}
	if err = installationServiceCommand("daemon-reload"); err != nil {
		return err
	}
	collectorAction := "restart"
	if tx.ServiceManager == "openrc" {
		collectorAction = "start"
		// OpenRC restarts dependents asynchronously when their dependency is
		// restarted. Stop our collector first so the installer owns its start.
		for _, service := range tx.Services {
			if service.Name == "selfguard-collector.service" && service.Active {
				if err = installationServiceCommand("stop", service.Name); err != nil {
					return err
				}
			}
		}
	}
	if claim.Profile.ExecutorEnabled {
		if err = installationServiceCommand("enable", "selfguard-executor.service"); err != nil {
			return err
		}
		if err = installationServiceCommand("restart", "selfguard-executor.service"); err != nil {
			return err
		}
	}
	if !claim.Profile.ExecutorEnabled {
		for _, service := range tx.Services {
			if service.Name == "selfguard-executor.service" && service.Exists {
				if err = installationServiceCommand("disable", "--now", service.Name); err != nil {
					return err
				}
			}
		}
	}
	if err = installationServiceCommand("enable", "selfguard-collector.service"); err != nil {
		return err
	}
	if err = installationServiceCommand(collectorAction, "selfguard-collector.service"); err != nil {
		return err
	}
	_ = installationRequest(client, server, id, "report", identity.Token, map[string]string{"status": "SERVICE_STARTING", "version": agentVersion}, nil)
	for attempt := 0; attempt < 24; attempt++ {
		accepted := false
		if installationServiceCommand("is-active", "--quiet", "selfguard-collector.service") == nil {
			if !tx.AcceptanceAttempted {
				tx.AcceptanceAttempted = true
				if err = tx.save(); err != nil {
					return err
				}
			}
			accepted = installationRequest(client, server, id, "report", identity.Token, map[string]string{"status": "SUCCEEDED", "version": agentVersion}, nil) == nil
		}
		if accepted {
			keepLocal = true
			if err = tx.commit(); err != nil {
				return fmt.Errorf("platform accepted; installation journal commit failed: %w", err)
			}
			if err = completeOfflineReceipt(claim.AssetID, agentVersion, claim.Profile.ExecutorEnabled); err != nil {
				return fmt.Errorf("platform accepted; local offline receipt update failed: %w", err)
			}
			fmt.Fprintln(output, "安装完成：目标版本服务运行与平台心跳验收通过。")
			if claim.Profile.HostWaf != nil {
				if err := finishInstallationHostWaf(id, config, output); err != nil {
					fmt.Fprintln(output, "Agent 已接入；Web 接入尚未完成：", err)
				}
			}
			return nil
		}
		time.Sleep(5 * time.Second)
	}
	if installationServiceCommand("is-active", "--quiet", "selfguard-collector.service") == nil {
		keepLocal = true
		if err = tx.commit(); err != nil {
			return err
		}
	}
	_ = installationRequest(client, server, id, "report", identity.Token, map[string]string{"status": "PARTIAL", "version": agentVersion}, nil)
	return errors.New("local installation retained; service or platform acceptance incomplete; retry the same task with its persisted identity")
}

func offlineInstallationState(profile installationProfile, version string) (map[string]any, error) {
	u, err := url.Parse(profile.Server)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || !validPlatformPath(u) {
		return nil, errors.New("offline profile requires HTTP or HTTPS origin")
	}
	return map[string]any{"status": "LOCAL_ONLY", "platformVerified": false, "version": version, "server": profile.Server, "executorPending": profile.ExecutorEnabled}, nil
}
func writeInstallationManagedFile(path string, content []byte, mode os.FileMode, transactions ...*installationTransaction) error {
	marker := path + ".selfguard-sha256"
	sum := sha256.Sum256(content)
	digest := hex.EncodeToString(sum[:])
	before, exists, err := readManagedInstallationFile(path)
	if err != nil {
		return err
	}
	if exists && bytes.Equal(before, content) {
		return nil
	}
	if err := installationWrite(path, content, mode, transactions...); err != nil {
		return err
	}
	return installationWrite(marker, []byte(digest), 0600, transactions...)
}
func writeInstallationConfig(path string, config Config, transactions ...*installationTransaction) error {
	content, err := json.Marshal(config)
	if err != nil {
		return err
	}
	return writeInstallationManagedFile(path, content, 0600, transactions...)
}
func runOfflineInstallation(envelopeFile, profileFile, root string, output io.Writer) (resultErr error) {
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		return errors.New("offline installation requires Linux root")
	}
	if err := requireInstallationHost(); err != nil {
		return err
	}
	unlock, err := installationLock()
	if err != nil {
		return err
	}
	defer unlock()
	if err = unfinishedInstallationTransactions(); err != nil {
		return err
	}
	raw, err := readBoundedFile(envelopeFile, 128<<10)
	if err != nil {
		return err
	}
	var envelope installationRelease
	if err = json.Unmarshal(raw, &envelope); err != nil {
		return err
	}
	raw, err = readBoundedFile(profileFile, 64<<10)
	if err != nil {
		return err
	}
	var profile installationProfile
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&profile); err != nil {
		return err
	}
	state, err := offlineInstallationState(profile, agentVersion)
	if err != nil {
		return err
	}
	candidate, err := os.ReadFile("/proc/self/exe")
	if err != nil {
		return err
	}
	var highest UpgradeManifest
	if err = read("/opt/selfguard-agent/highest-sequence.json", &highest); err != nil {
		return err
	}
	manifest, err := verifyInstallationRelease(envelope, root, candidate, "linux", runtime.GOARCH, highest.Sequence)
	if err != nil {
		return err
	}
	if manifest.Version != agentVersion {
		return errors.New("offline executable version mismatch")
	}
	config, err := applyInstallationProfile(installationCollectorConfig(profile.Server, root, profile.CACertificate), profile)
	if err != nil {
		return err
	}
	stateDir := config.StateDir
	if err = existingInstallationState(stateDir); err != nil {
		return err
	}
	identity, err := installationIdentity(stateDir)
	if err != nil {
		return err
	}
	if identity.AssetID != "" {
		return errors.New("registered hosts require authorized online installation or upgrade; existing identity retained")
	}
	uid, gid, err := installationAccount()
	if err != nil {
		return err
	}
	if err = os.MkdirAll("/etc/selfguard-agent", 0750); err != nil {
		return err
	}
	if err = executorTrustedDirectory("/etc/selfguard-agent", false); err != nil {
		return err
	}
	if err = preflightInstallationFiles("/opt/selfguard-agent", candidate, manifest.Sequence, managedInstallationConfigFiles()); err != nil {
		return err
	}
	tx, err := beginInstallationTransaction("/opt/selfguard-agent/install-transactions", "offline-"+strconv.FormatInt(time.Now().UnixNano(), 10), installationManagedPaths())
	if err != nil {
		return err
	}
	defer func() {
		if resultErr != nil && tx.Status == "OPEN" {
			resultErr = errors.Join(resultErr, tx.restoreServices())
		}
	}()
	if err = tx.captureServices(); err != nil {
		return err
	}
	if err = installManagedBinary("/opt/selfguard-agent", candidate, manifest.Sequence, tx); err != nil {
		return err
	}
	if err = tx.writePrivate("/opt/selfguard-agent/installed.json", manifest); err != nil {
		return err
	}
	if err = writePrivate("/opt/selfguard-agent/highest-sequence.json", manifest); err != nil {
		return err
	}
	if err = writeInstallationConfig("/etc/selfguard-agent/collector.json", config, tx); err != nil {
		return err
	}
	if err = protectCollectorFiles(stateDir, uid, gid); err != nil {
		return err
	}
	if err = writeInstallationService("selfguard-collector.service", false, config, tx); err != nil {
		return err
	}
	if err = installationServiceCommand("daemon-reload"); err != nil {
		return err
	}
	if err = installationServiceCommand("disable", "--now", "selfguard-collector.service"); err != nil {
		return err
	}
	if err = tx.writePrivate("/opt/selfguard-agent/offline-installation.json", state); err != nil {
		return err
	}
	if err = tx.commit(); err != nil {
		return err
	}
	fmt.Fprintln(output, "本地制品、账号、配置及服务文件已部署（LOCAL_ONLY）。服务保持禁用；未注册、未计为在线成功。联网后创建安装授权并运行同版本 --install 完成接入。")
	return nil
}
func removeInstallationManagedFile(path string) error {
	bytes, err := readBoundedFile(path, 1<<20)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	expected, err := readBoundedFile(path+".selfguard-sha256", 128)
	sum := sha256.Sum256(bytes)
	if err != nil || string(expected) != hex.EncodeToString(sum[:]) {
		return errors.New("refusing to remove modified or unmanaged file")
	}
	if err = os.Remove(path); err != nil {
		return err
	}
	return os.Remove(path + ".selfguard-sha256")
}
func runUninstallation(output io.Writer) error {
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		return errors.New("uninstall requires Linux root")
	}
	if err := requireInstallationHost(); err != nil {
		return err
	}
	unlock, err := installationLock()
	if err != nil {
		return err
	}
	defer unlock()
	if err = unfinishedInstallationTransactions(); err != nil {
		return err
	}
	if err := executorTrustedConfig("/etc/selfguard-agent/collector.json"); err != nil {
		return err
	}
	var config Config
	if err := read("/etc/selfguard-agent/collector.json", &config); err != nil {
		return err
	}
	if !managedStatePath.MatchString(config.StateDir) || config.UpgradeInstallRoot != "/opt/selfguard-agent" {
		return errors.New("unrecognized installation layout")
	}
	var identity Identity
	if err := read(filepath.Join(config.StateDir, "identity.json"), &identity); err != nil {
		return err
	}
	if identity.Token == "" {
		return errors.New("platform credential required for managed uninstall; state retained")
	}
	client, err := clientForConfig(config)
	if err != nil {
		return err
	}
	raw, _ := json.Marshal(map[string]string{"assetId": identity.AssetID})
	request, err := http.NewRequest("POST", strings.TrimSuffix(config.Server, "/")+"/api/agent/uninstall", bytes.NewReader(raw))
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+identity.Token)
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return errors.New("platform uninstall precheck unavailable; local installation retained")
	}
	response.Body.Close()
	if response.StatusCode != 200 && response.StatusCode != 201 {
		return errors.New("platform blocked uninstall: pending tasks or credential mismatch; installation retained")
	}
	for _, service := range []string{"selfguard-collector.service", "selfguard-executor.service"} {
		if _, err = os.Stat(installationServicePath(service)); err == nil {
			if err = installationServiceCommand("disable", "--now", service); err != nil {
				return err
			}
			if err = removeInstallationManagedFile(installationServicePath(service)); err != nil {
				return err
			}
		}
	}
	if err = installationServiceCommand("daemon-reload"); err != nil {
		return err
	}
	// Retain executable and identity/recovery material for diagnosis. Services and
	// platform credential are disabled; no managed business file is removed.
	fmt.Fprintln(output, "已停用并卸载受管服务、撤销平台凭据；保留制品、身份及恢复材料。业务文件与平台历史保留。")
	return nil
}
