package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	AllowHTTP               bool
	ApplicationInputs       []ApplicationInput
	ReadOnly                bool
	ProxyURL                string
	ProxyMode               string
	CPUQuotaPercent         int
	CACertificate           string
	ExecutorSocket          string
	ExecutorPublicKey       string
	ExecutorAssetID         string
	ExecutorAllowedUID      *uint32
	MaxCPUs                 int
	MaxMemoryBytes          int64
	MaxQueueBytes           int64
	BytesPerSecond          int64
	UpgradePublicKey        string
	UpgradeFixtureRoot      string
	UpgradeInstallRoot      string
	UpgradeOrigins          []string
	remoteUpgrade           bool
	upgradePublicExecutable bool
	Server                  string
	EnrollmentToken         string
	StateDir                string
	AllowedRoot             string
	AllowedServices         []string
	Development             bool
	Checks                  []Check
	FIMPaths                []string
	LogPaths                []string
	LogIncludeMessage       bool
	LogRedactions           []string
}
type Check struct {
	RuleID         string
	RuleName       string
	RuleSeverity   string
	HealthService  string `json:"healthService,omitempty"`
	OriginalTaskID string `json:"originalTaskId"`
	Type           string
	Service        string
	State          string
	ExpectedState  string
	Key            string
	ExpectedValue  string
	Value          string
	Path           string
	Mode           string
}
type Identity struct {
	EnrollmentSecret string `json:"enrollmentSecret"`
	Identity         string
	AssetID          string `json:"assetId"`
	Token            string `json:"token"`
}
type Task struct {
	AssetID       string             `json:"assetId,omitempty"`
	Authorization *TaskAuthorization `json:"authorization,omitempty"`
	ID            string             `json:"id"`
	Template      string             `json:"template"`
	Parameters    Check              `json:"parameters"`
	ExpiresAt     time.Time          `json:"expiresAt"`
}
type Result struct {
	Success  bool              `json:"success"`
	Evidence string            `json:"evidence"`
	Details  map[string]string `json:"details,omitempty"`
}
type Pending struct {
	Path string
	Body json.RawMessage
}
type Agent struct {
	PolicyFindings []map[string]any
	LogContexts    []hostLogContext
	serviceRunner  func(context.Context, ...string) (string, error)
	serviceTimeout time.Duration
	RemoteChecks   []Check
	RemoteFIM      []string
	LogRules       []PolicyRule
	CollectorState map[string]fileState
	Config         Config
	Identity       Identity
	Client         *http.Client
	Queue          []Pending
	Done           map[string]Result
	Ack            map[string]bool
}

func writePrivate(path string, v any) error {
	b, e := json.Marshal(v)
	if e != nil {
		return e
	}
	f, e := os.OpenFile(path+".tmp", os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	if e = f.Chmod(0600); e == nil {
		_, e = f.Write(b)
	}
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e != nil {
		return e
	}
	if ce != nil {
		return ce
	}
	if e := os.Rename(path+".tmp", path); e != nil {
		return e
	}
	return syncParent(path)
}
func read(path string, v any) error {
	b, e := os.ReadFile(path)
	if os.IsNotExist(e) {
		return nil
	}
	if e != nil {
		return e
	}
	return json.Unmarshal(b, v)
}
func New(c Config) (*Agent, error) {
	if err := validateApplicationInputs(c.AllowedRoot, c.ApplicationInputs); err != nil {
		return nil, err
	}
	if _, err := compileLogRedactions(c); err != nil {
		return nil, err
	}
	if c.MaxCPUs < 0 || c.MaxMemoryBytes < 0 || c.MaxQueueBytes < 0 || c.BytesPerSecond < 0 {
		return nil, errors.New("resource budgets must be nonnegative")
	}
	u, e := url.Parse(c.Server)
	if e != nil {
		return nil, e
	}
	host := u.Hostname()
	ip := net.ParseIP(host)
	if u.Scheme != "https" && !(u.Scheme == "http" && (c.AllowHTTP || c.Development || host == "localhost" || (ip != nil && ip.IsLoopback()))) {
		return nil, errors.New("HTTP requires explicit AllowHTTP configuration; HTTPS remains the default")
	}
	if u.Host == "" || u.User != nil || !validPlatformPath(u) {
		return nil, errors.New("invalid server")
	}
	if c.StateDir == "" {
		return nil, errors.New("state directory required")
	}
	if e = os.MkdirAll(c.StateDir, 0700); e != nil {
		return nil, e
	}
	client, err := clientForConfig(c)
	if err != nil {
		return nil, err
	}
	client.Timeout = 15 * time.Second
	a := &Agent{Config: c, Done: map[string]Result{}, Ack: map[string]bool{}, Client: client}
	for _, x := range []struct {
		p string
		v any
	}{{"identity.json", &a.Identity}, {"queue.json", &a.Queue}, {"done.json", &a.Done}, {"ack.json", &a.Ack}} {
		if e = read(filepath.Join(c.StateDir, x.p), x.v); e != nil {
			return nil, e
		}
	}
	return a, nil
}
func (a *Agent) request(method, path, token string, body any, out any) error {
	var b []byte
	var e error
	if body != nil {
		b, e = json.Marshal(body)
		if e != nil {
			return e
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	r, e := http.NewRequestWithContext(ctx, method, strings.TrimRight(a.Config.Server, "/")+"/api"+path, bytes.NewReader(b))
	if e != nil {
		return e
	}
	if a.Config.BytesPerSecond > 0 && r.Body != nil {
		r.Body = io.NopCloser(&pacedReader{reader: r.Body, ctx: r.Context(), rate: a.Config.BytesPerSecond})
	}
	r.Header.Set("Authorization", "Bearer "+token)
	r.Header.Set("Content-Type", "application/json")
	resp, e := a.Client.Do(r)
	if e != nil {
		return errors.New("server unavailable")
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("server status %d", resp.StatusCode)
	}
	if out != nil {
		var reader io.Reader = resp.Body
		if a.Config.BytesPerSecond > 0 {
			reader = &pacedReader{reader: reader, ctx: r.Context(), rate: a.Config.BytesPerSecond}
		}
		limit := int64(2 << 20)
		if path == "/agent/host-waf/bootstrap" {
			limit = (8 << 20) + (64 << 10)
		}
		return json.NewDecoder(io.LimitReader(reader, limit)).Decode(out)
	}
	return nil
}
func (a *Agent) enroll() error {
	if a.Identity.Token != "" && a.Identity.AssetID != "" {
		return nil
	}
	host, _ := os.Hostname()
	if a.Identity.EnrollmentSecret == "" {
		b := make([]byte, 32)
		if _, e := rand.Read(b); e != nil {
			return e
		}
		a.Identity.EnrollmentSecret = base64.RawURLEncoding.EncodeToString(b)
	}
	if a.Identity.Identity == "" {
		a.Identity.Identity = fmt.Sprintf("%s-%d", host, time.Now().UnixNano())
		if e := writePrivate(filepath.Join(a.Config.StateDir, "identity.json"), a.Identity); e != nil {
			return e
		}
	}
	if e := writePrivate(filepath.Join(a.Config.StateDir, "identity.json"), a.Identity); e != nil {
		return e
	}
	if e := a.request("POST", "/agent/enroll", a.Config.EnrollmentToken, map[string]string{"identity": a.Identity.Identity, "credential": a.Identity.EnrollmentSecret, "hostname": host, "os": runtime.GOOS, "agentVersion": agentVersion}, &a.Identity); e != nil {
		return e
	}
	if a.Identity.Token == "" {
		return errors.New("empty enrollment token")
	}
	return writePrivate(filepath.Join(a.Config.StateDir, "identity.json"), a.Identity)
}

// Refuse every symlink component, including the configured root itself.
func safePath(root, path string) error {
	if root == "" {
		return errors.New("remediation disabled")
	}
	r, e := filepath.Abs(root)
	if e != nil {
		return e
	}
	p, e := filepath.Abs(path)
	if e != nil {
		return e
	}
	rel, e := filepath.Rel(r, p)
	if e != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return errors.New("outside allowed root")
	}
	cur := string(os.PathSeparator)
	for _, part := range strings.Split(strings.TrimPrefix(p, cur), string(os.PathSeparator)) {
		cur = filepath.Join(cur, part)
		s, e := os.Lstat(cur)
		if e != nil {
			return e
		}
		if s.Mode()&os.ModeSymlink != 0 {
			return errors.New("symlink refused")
		}
	}
	return nil
}
func (a *Agent) executeMutation(t Task) Result {
	fail := func(e error) Result { return Result{Evidence: e.Error()} }
	if _, err := os.Stat(filepath.Join(a.Config.StateDir, "service-recovery.json")); !os.IsNotExist(err) {
		return fail(errors.New("service recovery pending or inaccessible; further task mutation refused"))
	}

	if t.Template == "SERVICE_STATE" {
		return a.executeService(t)
	}
	if t.Template == "CONFIG_VALUE" {
		return a.executeConfig(t)
	}
	if t.Template != "FILE_PERMISSION" {
		return fail(errors.New("unsupported template"))
	}
	if t.ExpiresAt.IsZero() || !t.ExpiresAt.After(time.Now()) {
		return fail(errors.New("task expired or missing expiry"))
	}
	if e := safePath(a.Config.AllowedRoot, t.Parameters.Path); e != nil {
		return fail(e)
	}
	mode, e := strconv.ParseUint(t.Parameters.Mode, 8, 12)
	if e != nil || (mode != 0600 && mode != 0640 && mode != 0644) {
		return fail(errors.New("invalid permission mode"))
	}
	f, e := openTarget(t.Parameters.Path)
	if e != nil {
		return fail(e)
	}
	defer f.Close()
	before, e := f.Stat()
	if e != nil {
		return fail(e)
	}
	if !before.Mode().IsRegular() || multipleLinks(before) {
		return fail(errors.New("regular files only"))
	}
	current, e := os.Lstat(t.Parameters.Path)
	if e != nil || !os.SameFile(before, current) || current.Mode()&os.ModeSymlink != 0 {
		return fail(errors.New("file changed during precheck"))
	}
	if e = f.Chmod(os.FileMode(mode)); e != nil {
		return fail(e)
	}
	after, e := f.Stat()
	if e != nil || after.Mode().Perm() != os.FileMode(mode) {
		rollback := f.Chmod(before.Mode().Perm())
		return Result{Evidence: "verification failed", Details: map[string]string{"rollback": fmt.Sprint(rollback)}}
	}
	return Result{Success: true, Evidence: "permissions verified; independent server verification required", Details: map[string]string{"previousMode": fmt.Sprintf("%04o", before.Mode().Perm()), "mode": fmt.Sprintf("%04o", mode)}}
}
func (a *Agent) enqueue(path string, body any) error {
	b, e := json.Marshal(body)
	if e != nil {
		return e
	}
	if len(b) > 1<<20 {
		return errors.New("report too large")
	}
	if len(a.Queue) >= 128 {
		return errors.New("offline queue full")
	}
	if a.Config.MaxQueueBytes > 0 {
		size := int64(len(b))
		for _, p := range a.Queue {
			size += int64(len(p.Body))
		}
		if size > a.Config.MaxQueueBytes {
			return errors.New("offline queue byte budget reached")
		}
	}
	a.Queue = append(a.Queue, Pending{path, b})
	return writePrivate(filepath.Join(a.Config.StateDir, "queue.json"), a.Queue)
}
func (a *Agent) flush() error {
	for len(a.Queue) > 0 {
		p := a.Queue[0]
		if e := a.request("POST", p.Path, a.Identity.Token, p.Body, nil); e != nil {
			return e
		}
		a.Queue = a.Queue[1:]
		if e := writePrivate(filepath.Join(a.Config.StateDir, "queue.json"), a.Queue); e != nil {
			return e
		}
	}
	return nil
}
func (a *Agent) cycle() error {
	if err := a.ensureRunningRelease(); err != nil {
		return err
	}
	if _, err := os.Stat(filepath.Join(a.Config.StateDir, "service-recovery.json")); err == nil {
		return errors.New("pending service recovery: verify recorded state and application health before removing recovery marker; agent paused")
	} else if !os.IsNotExist(err) {
		return err
	}

	if a.Config.UpgradeInstallRoot != "" {
		if _, e := os.Stat(filepath.Join(a.Config.UpgradeInstallRoot, "upgrade-recovery.json")); e == nil {
			return errors.New("pending upgrade recovery: agent paused until administrator rollback and verification")
		} else if !os.IsNotExist(e) {
			return e
		}
	}

	if _, e := os.Stat(filepath.Join(a.Config.StateDir, "config-recovery.json")); e == nil {
		return errors.New("pending configuration recovery: restore private backup and remove recovery marker after manual verification; agent paused")
	} else if !os.IsNotExist(e) {
		return e
	}
	if e := a.enroll(); e != nil {
		return e
	}
	online := a.flush() == nil
	if online {
		online = a.sendResults() == nil
	}
	host, _ := os.Hostname()
	a.policy()
	findings := a.collectFiles()
	findings = append(findings, a.collectBaselines()...)
	packageList, packageStatus := packages()
	distribution, distributionStatus := distributionInventory("/etc/os-release")
	ports, portStatus := portInventory("/proc/net")
	services, serviceStatus := serviceInventory()
	components, componentStatus := applicationInventory(a.Config.AllowedRoot, a.Config.ApplicationInputs)
	if e := a.heartbeat(map[string]any{"hostname": host, "os": runtime.GOOS, "architecture": runtime.GOARCH, "distribution": distribution, "distributionCollection": distributionStatus, "cpus": runtime.NumCPU(), "components": components, "componentCollection": componentStatus, "packages": packageList, "packageCollection": packageStatus, "ports": ports, "portCollection": portStatus, "services": services, "serviceCollection": serviceStatus, "upgradeStatus": a.upgradeStatus(), "agentDiagnostics": map[string]any{"version": agentVersion, "managedReleaseDownload": true, "capabilities": []string{"data-security-v1", "traffic-capture-v1", "nginx-onboarding-v1"}, "proxyMode": a.Config.ProxyMode, "readOnlyCollector": a.Config.ReadOnly, "executorEnabled": a.Config.ExecutorSocket != "", "queuedReports": len(a.Queue), "previousDeliverySucceeded": online, "maxCPUs": a.Config.MaxCPUs, "maxMemoryBytes": a.Config.MaxMemoryBytes, "maxQueueBytes": a.Config.MaxQueueBytes, "bytesPerSecond": a.Config.BytesPerSecond}}, findings); e != nil {
		return e
	}
	if e := a.commitCollectors(); e != nil {
		return e
	}
	if e := a.flush(); e != nil {
		return e
	}
	if err := a.rolloutCycle(); err != nil {
		return err
	}
	var response struct {
		Items []Task `json:"items"`
	}
	if e := a.request("GET", "/agent/tasks", a.Identity.Token, nil, &response); e != nil {
		return e
	}
	for _, t := range response.Items {
		r, ok := a.Done[t.ID]
		if !ok {
			if len(a.Done) >= 10000 {
				return errors.New("task history capacity reached")
			}
			a.Done[t.ID] = Result{Evidence: "execution interrupted; manual review required"}
			if e := writePrivate(filepath.Join(a.Config.StateDir, "done.json"), a.Done); e != nil {
				return e
			}
			r = a.execute(t)
			a.Done[t.ID] = r
			if e := writePrivate(filepath.Join(a.Config.StateDir, "done.json"), a.Done); e != nil {
				return e
			}
		}

	}
	return a.sendResults()
}
func main() {
	if len(os.Args) == 3 && os.Args[1] == "--expire-traffic" {
		if err := expireTrafficCapture(os.Args[2]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}

	if len(os.Args) == 3 && os.Args[1] == "--onboard-nginx" {
		if err := runHostWafOnboarding(os.Args[2], os.Stdout); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	if len(os.Args) == 3 && os.Args[1] == "--rollback-nginx" {
		if err := runHostWafRollback(os.Args[2], os.Stdout); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	if len(os.Args) == 3 && os.Args[1] == "--publish-traffic" {
		if err := publishNetworkReport(os.Args[2]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}

	if len(os.Args) == 4 && os.Args[1] == "--capture-traffic" {
		if err := runTrafficCapture(os.Args[2], os.Args[3], os.Stdout); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}

	if len(os.Args) == 5 && os.Args[1] == "--install-offline" {
		if err := runOfflineInstallation(os.Args[2], os.Args[3], os.Args[4], os.Stdout); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	if len(os.Args) == 2 && os.Args[1] == "--uninstall" {
		if err := runUninstallation(os.Stdout); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}

	if len(os.Args) == 3 && os.Args[1] == "--recover-installation" {
		if err := recoverInstallation(os.Args[2], os.Stdout); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	if len(os.Args) == 5 && os.Args[1] == "--install" {
		if err := runInstallation(os.Args[2], os.Args[3], os.Args[4], os.Stdin, os.Stdout); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}

	if len(os.Args) == 2 && os.Args[1] == "--test-rule" {
		if err := runRuleTest(os.Stdin, os.Stdout); err != nil {
			fmt.Fprintln(os.Stderr, "invalid rule test fixture")
			os.Exit(1)
		}
		return
	}
	if len(os.Args) == 2 && os.Args[1] == "--self-test" {
		fmt.Println("selfguard-agent: healthy")
		return
	}
	if os.Getenv("SELFGUARD_OPENRC_SERVICE") == "1" {
		manager, err := currentInstallationInit()
		if err != nil || manager != "openrc" {
			fmt.Fprintln(os.Stderr, "OpenRC service requires its running host init system")
			os.Exit(1)
		}
		if err := requireNoNewPrivileges(); err != nil {
			fmt.Fprintln(os.Stderr, "OpenRC service privilege boundary was not inherited")
			os.Exit(1)
		}
	}
	c := Config{AllowHTTP: os.Getenv("AGENT_ALLOW_HTTP") == "true", Server: os.Getenv("AGENT_SERVER"), EnrollmentToken: os.Getenv("AGENT_ENROLLMENT_TOKEN"), StateDir: os.Getenv("AGENT_STATE_DIR"), AllowedRoot: os.Getenv("AGENT_ALLOWED_ROOT"), Development: os.Getenv("AGENT_DEVELOPMENT") == "true"}
	if p := os.Getenv("AGENT_CONFIG"); p != "" {
		if len(os.Args) == 2 && (os.Args[1] == "--executor" || os.Args[1] == "--executor-public-key") {
			if err := executorTrustedConfig(p); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
		}
		if e := read(p, &c); e != nil {
			fmt.Fprintln(os.Stderr, "invalid configuration")
			os.Exit(1)
		}
	}
	if len(os.Args) > 1 {
		var err error
		switch {
		case len(os.Args) == 2 && os.Args[1] == "--executor-public-key":
			var publicKey string
			publicKey, err = executorPublicKey(c)
			if err == nil {
				fmt.Println(publicKey)
			}
		case len(os.Args) == 2 && os.Args[1] == "--executor":
			err = runExecutor(c)
		case len(os.Args) == 2 && (os.Args[1] == "--rollback-upgrade" || os.Args[1] == "--rollback-fixture"):
			err = rollbackUpgrade(c)
		case len(os.Args) == 4 && (os.Args[1] == "--stage-upgrade" || os.Args[1] == "--upgrade-fixture"):
			var b []byte
			var envelope SignedUpgrade
			b, err = readBoundedFile(os.Args[2], 64<<10)
			if err == nil {
				err = json.Unmarshal(b, &envelope)
			}
			if err == nil {
				b, err = readBoundedFile(os.Args[3], 64<<20)
			}
			if err == nil {
				err = stageUpgrade(c, envelope, b, candidateHealth)
			}
		default:
			err = errors.New("unknown command")
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			if errors.Is(err, errUpgradeRestart) {
				os.Exit(75)
			}
			os.Exit(1)
		}
		return
	}
	applyResourceBudgets(c)
	a, e := New(c)
	if e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
	for {
		if e := a.cycle(); e != nil {
			if errors.Is(e, errUpgradeRestart) {
				if err := writePrivate(filepath.Join(c.StateDir, "rollout-restarting"), map[string]string{"status": "restart requested"}); err != nil {
					fmt.Fprintln(os.Stderr, err)
					os.Exit(1)
				}
				os.Exit(75)
			}
			fmt.Fprintln(os.Stderr, e)
		}
		time.Sleep(30 * time.Second)
	}
}
