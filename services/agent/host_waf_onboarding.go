package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type HostWafPlan struct {
	ExpectedPlannedConfigSHA256 string  `json:"expectedPlannedConfigSha256,omitempty"`
	WafCPUQuota                 float64 `json:"wafCPUQuota,omitempty"`
	WafMemoryBytes              int64   `json:"wafMemoryBytes,omitempty"`
	ImageArchiveSHA256          string  `json:"imageArchiveSha256,omitempty"`
	ImageArchiveBytes           int64   `json:"imageArchiveBytes,omitempty"`
	BusinessMode                string  `json:"businessMode,omitempty"`
	ListenPort                  int     `json:"listenPort,omitempty"`
	CertificateFile             string  `json:"certificateFile,omitempty"`
	CertificateKeyFile          string  `json:"certificateKeyFile,omitempty"`
	ExpectedConfigSHA256        string  `json:"expectedConfigSha256,omitempty"`
	ExpectedNginxSHA256         string  `json:"expectedNginxSha256,omitempty"`
	Schema                      string  `json:"schema"`
	AssetID                     string  `json:"assetId"`
	SiteID                      string  `json:"siteId"`
	Hostname                    string  `json:"hostname"`
	Upstream                    string  `json:"upstream"`
	Image                       string  `json:"image"`
	NginxConfig                 string  `json:"nginxConfig"`
	WafPort                     int     `json:"wafPort"`
	EntryURL                    string  `json:"entryUrl"`
	HealthPath                  string  `json:"healthPath"`
	Mode                        string  `json:"mode"`
}

func hostTool(name string, args ...string) (string, error) {
	path := "/usr/bin/docker"
	if name == "nginx" {
		path = "/usr/sbin/nginx"
	}
	if err := executorTrustedConfig(path); err != nil {
		return "", errors.New("trusted " + name + " executable required at " + path)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C"}
	out := &cappedOutput{}
	cmd.Stdout = out
	cmd.Stderr = io.Discard
	if err := cmd.Run(); err != nil {
		return "", errors.New(name + " operation failed")
	}
	if out.truncated {
		return "", errors.New(name + " output exceeded budget")
	}
	return strings.TrimSpace(string(out.b)), nil
}
func runNginx(args ...string) error { _, err := hostTool("nginx", args...); return err }
func (p HostWafPlan) validate() error {
	if p.Schema != "selfguard-nginx-v1" || !regexp.MustCompile(`^[a-zA-Z0-9-]{1,64}$`).MatchString(p.AssetID) || !regexp.MustCompile(`^[a-zA-Z0-9-]{1,64}$`).MatchString(p.SiteID) || !regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9.-]{0,252}$`).MatchString(p.Hostname) || p.WafPort < 1024 || p.WafPort > 65535 || (p.Mode != "OBSERVE" && p.Mode != "BLOCK") || !regexp.MustCompile(`^(?:sha256:[a-f0-9]{64}|[A-Za-z0-9./_:-]+@sha256:[a-f0-9]{64})$`).MatchString(p.Image) {
		return errors.New("invalid or mutable host WAF plan")
	}
	if p.BusinessMode != "" && p.BusinessMode != "EXISTING" && p.BusinessMode != "NEW" {
		return errors.New("unknown nginx business mode")
	}
	if p.BusinessMode == "NEW" {
		if _, err := newNginxSite(p); err != nil {
			return err
		}
	} else if p.ListenPort != 0 || p.CertificateFile != "" || p.CertificateKeyFile != "" {
		return errors.New("new site fields cannot modify existing nginx ingress")
	}
	if p.ExpectedConfigSHA256 != "" && p.ExpectedConfigSHA256 != "ABSENT" && !regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(p.ExpectedConfigSHA256) {
		return errors.New("invalid nginx source digest")
	}
	if p.ExpectedNginxSHA256 != "" && !regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(p.ExpectedNginxSHA256) {
		return errors.New("invalid nginx full configuration digest")
	}
	if p.ImageArchiveSHA256 != "" || p.ImageArchiveBytes != 0 {
		if !regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(p.ImageArchiveSHA256) || p.ImageArchiveBytes < 1 || p.ImageArchiveBytes > 64<<20 {
			return errors.New("invalid managed WAF image archive")
		}
	}
	if (p.WafCPUQuota != 0 || p.WafMemoryBytes != 0) && (p.WafCPUQuota != 4 || p.WafMemoryBytes != 1073741824) {
		return errors.New("invalid bounded WAF runtime resource profile")
	}
	if p.ExpectedPlannedConfigSHA256 != "" && !regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(p.ExpectedPlannedConfigSHA256) {
		return errors.New("invalid planned nginx digest")
	}
	entry, err := url.Parse(p.EntryURL)
	if err != nil || entry.Hostname() != "127.0.0.1" || (entry.Scheme != "http" && entry.Scheme != "https") || entry.User != nil || entry.RawQuery != "" || entry.Fragment != "" || entry.Path != "/" {
		return errors.New("explicit local nginx ingress origin required")
	}
	if !regexp.MustCompile(`^/[A-Za-z0-9_./-]*$`).MatchString(p.HealthPath) || len(p.HealthPath) > 500 || !filepath.IsAbs(p.NginxConfig) || filepath.Clean(p.NginxConfig) != p.NginxConfig {
		return errors.New("invalid health or nginx path")
	}
	return nil
}

type ingressProbe struct {
	status int
	body   []byte
	target string
}

func probeIngress(p HostWafPlan, query string) (ingressProbe, error) {
	origin, _ := url.Parse(p.EntryURL)
	target := *origin
	target.Path = p.HealthPath
	target.RawQuery = query
	req, err := http.NewRequest("GET", target.String(), nil)
	if err != nil {
		return ingressProbe{}, err
	}
	req.Host = p.Hostname
	client := &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }, Transport: &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{ServerName: p.Hostname, MinVersion: tls.VersionTLS12}}}
	resp, err := client.Do(req)
	if err != nil {
		return ingressProbe{}, errors.New("nginx ingress probe unavailable or certificate invalid")
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 65537))
	if err != nil || len(b) > 65536 {
		return ingressProbe{}, errors.New("stable health response must fit within 64 KiB")
	}
	return ingressProbe{resp.StatusCode, b, target.RequestURI()}, nil
}
func verifyHostWafRequest(state string, p HostWafPlan, probe ingressProbe, synthetic bool) error {
	var entries []struct {
		SiteID  string `json:"siteId"`
		Status  int    `json:"status"`
		Context *struct {
			Target    string `json:"requestTargetSha256"`
			Forwarded bool   `json:"forwarded"`
			Action    string `json:"action"`
		} `json:"context"`
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		b, err := readBoundedFile(filepath.Join(state, "access.json"), 8<<20)
		if err == nil && json.Unmarshal(b, &entries) == nil {
			for _, row := range entries {
				if row.SiteID == p.SiteID && row.Context != nil && row.Context.Target == contentDigest([]byte(probe.target)) && row.Status == probe.status {
					if synthetic {
						if p.Mode == "BLOCK" && row.Context.Action == "BLOCK" && !row.Context.Forwarded && row.Status == 403 {
							return nil
						}
						if p.Mode == "OBSERVE" && row.Context.Action == "OBSERVE" && row.Context.Forwarded && row.Status < 400 {
							return nil
						}
					} else if row.Context.Forwarded && row.Status >= 200 && row.Status < 300 {
						return nil
					}
				}
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("actual nginx → WAF evidence missing or outcome incorrect (mode=%s HTTP=%d records=%d)", p.Mode, probe.status, len(entries))
}
func verifyHostWafIngress(state string, p HostWafPlan, before ingressProbe, nonce string) error {
	var lastErr error
	for attempt := 0; attempt < 4; attempt++ {
		query := "selfguard_probe=" + nonce + "-" + strconv.Itoa(attempt)
		normal, err := probeIngress(p, query)
		if err == nil && (normal.status != before.status || !bytes.Equal(normal.body, before.body)) {
			err = errors.New("normal ingress response changed")
		}
		if err == nil {
			err = verifyHostWafRequest(state, p, normal, false)
		}
		if err == nil {
			attack, probeErr := probeIngress(p, query+"&selfguard_sample=union%20select")
			if probeErr == nil {
				probeErr = verifyHostWafRequest(state, p, attack, true)
			}
			if probeErr == nil {
				return nil
			}
			err = probeErr
		}
		lastErr = err
		time.Sleep(100 * time.Millisecond)
	}
	return lastErr
}

func runHostWafOnboarding(planFile string, out io.Writer) (resultErr error) {
	if err := executorPlatform(); err != nil {
		return err
	}
	if err := executorTrustedConfig(planFile); err != nil {
		return err
	}
	b, err := readBoundedFile(planFile, 16<<10)
	if err != nil {
		return err
	}
	var p HostWafPlan
	if err = decodeExecutorParameters(b, &p); err != nil {
		return err
	}
	if err = p.validate(); err != nil {
		return err
	}
	source, err := nginxPlanSource(p)
	if err != nil {
		return err
	}
	if p.BusinessMode == "NEW" && p.ExpectedNginxSHA256 == "" {
		return errors.New("new business requires reviewed nginx preflight")
	}
	if p.ExpectedNginxSHA256 != "" {
		preview, e := inspectNginxPlan(p)
		if e != nil {
			return e
		}
		if preview.NginxSHA256 != p.ExpectedNginxSHA256 || preview.ConfigSHA256 != p.ExpectedConfigSHA256 {
			return errors.New("nginx configuration changed since reviewed preflight")
		}
	}
	local := "127.0.0.1:" + strconv.Itoa(p.WafPort)
	after, err := planNginxOnboarding(source, p.Hostname, p.Upstream, local)
	if err != nil {
		return err
	}
	if p.ExpectedPlannedConfigSHA256 != "" && contentDigest(after) != p.ExpectedPlannedConfigSHA256 {
		return errors.New("planned nginx change differs from reviewed preflight")
	}
	a, err := hostNetworkAgent()
	if err != nil {
		return err
	}
	if a.Identity.AssetID != p.AssetID {
		return errors.New("onboarding plan belongs to another asset")
	}
	reported := false
	defer func() {
		if resultErr != nil && !reported {
			report := map[string]any{"schema": p.Schema, "siteId": p.SiteID, "mode": p.Mode, "status": "FAILED", "updatedAt": time.Now().UTC().Format(time.RFC3339Nano), "transactionDir": filepath.Join("/var/lib/selfguard-host-waf", p.AssetID, "nginx"), "message": "Onboarding preflight failed; nginx configuration was not changed"}
			_ = a.request("POST", "/agent/network-report", a.Identity.Token, report, nil)
		}
	}()
	if err = ensureHostWafImage(a, p); err != nil {
		return err
	}
	occupied, err := net.Listen("tcp4", local)
	if err != nil {
		return errors.New("selected local WAF port is already in use")
	}
	occupied.Close()
	var before ingressProbe
	if p.BusinessMode == "NEW" {
		before, err = probeBusinessUpstream(p)
	} else {
		before, err = probeIngress(p, "")
	}
	if err != nil || before.status < 200 || before.status >= 300 {
		return errors.New("nginx must serve a stable successful health response before onboarding")
	}
	root := "/var/lib/selfguard-host-waf"
	if err = os.MkdirAll(root, 0700); err != nil {
		return err
	}
	if err = executorTrustedDirectory(root, true); err != nil {
		return err
	}
	state := filepath.Join(root, p.AssetID)
	if err = os.Mkdir(state, 0700); err != nil {
		return errors.New("host WAF state already exists; inspect or roll back its transaction before retry")
	}
	if err = writePrivate(filepath.Join(state, "plan.json"), p); err != nil {
		return err
	}
	// Retain all journals; an interrupted attempt is never silently overwritten.
	var bootstrap struct {
		AssetID   string          `json:"assetId"`
		PublicKey string          `json:"publicKey"`
		Config    json.RawMessage `json:"config"`
	}
	if err = a.request("GET", "/agent/host-waf/bootstrap", a.Identity.Token, nil, &bootstrap); err != nil {
		return err
	}
	var config struct {
		Sites []struct {
			ID       string `json:"id"`
			Hostname string `json:"hostname"`
			Upstream string `json:"upstream"`
			Mode     string `json:"mode"`
			Enabled  bool   `json:"enabled"`
			Config   struct {
				Trusted      []string `json:"trustedProxyCidrs"`
				NginxIngress bool     `json:"nginxIngress"`
			} `json:"config"`
		} `json:"sites"`
	}
	if json.Unmarshal(bootstrap.Config, &config) != nil || bootstrap.AssetID != p.AssetID || len(config.Sites) != 1 {
		return errors.New("exact assigned site configuration required")
	}
	site := config.Sites[0]
	trusted := false
	for _, cidr := range site.Config.Trusted {
		if cidr == "127.0.0.1/32" {
			trusted = true
		}
	}
	if site.ID != p.SiteID || site.Hostname != p.Hostname || strings.TrimSuffix(site.Upstream, "/") != p.Upstream || site.Mode != p.Mode || !site.Enabled || !trusted || !site.Config.NginxIngress {
		return errors.New("platform site changed or loopback trust missing; regenerate the plan")
	}
	var credential struct {
		Token  string `json:"token"`
		NodeID string `json:"nodeId"`
	}
	if err = a.request("POST", "/agent/host-waf/credential", a.Identity.Token, map[string]any{}, &credential); err != nil {
		return err
	}
	wafState := filepath.Join(state, "waf")
	if err = os.Mkdir(wafState, 0700); err != nil {
		return err
	}
	if err = os.WriteFile(filepath.Join(wafState, "config.json"), bootstrap.Config, 0600); err != nil {
		return err
	}
	if err = os.Chown(filepath.Join(wafState, "config.json"), 10001, 10001); err != nil {
		return err
	}
	if err = os.Chown(wafState, 10001, 10001); err != nil {
		return err
	}
	if err = writeHostWafTrustFile(filepath.Join(state, "rule-public-key"), []byte(bootstrap.PublicKey)); err != nil {
		return err
	}
	env := "WAF_LISTEN=" + local + "\nWAF_STATE_DIR=/state\nWAF_CONFIG=/state/config.json\nWAF_NODE_ID=" + credential.NodeID + "\nWAF_API_URL=" + strings.TrimSuffix(a.Config.Server, "/") + "\nWAF_TOKEN=" + credential.Token + "\n"
	if a.Config.AllowHTTP {
		env += "WAF_ALLOW_HTTP=true\n"
	}
	cpu, memory := "0.5", "256m"
	if p.WafCPUQuota != 0 {
		cpu = strconv.FormatFloat(p.WafCPUQuota, 'f', -1, 64)
		memory = strconv.FormatInt(p.WafMemoryBytes, 10)
	}
	args := []string{"run", "-d", "--name", "selfguard-host-waf-" + p.AssetID, "--network", "host", "--pull", "never", "--user", "10001:10001", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--pids-limit", "64", "--memory", memory, "--cpus", cpu, "--restart", "unless-stopped", "--tmpfs", "/tmp:rw,noexec,nosuid,size=16m", "--mount", "type=bind,src=" + wafState + ",dst=/state", "--env-file", filepath.Join(state, "node.env")}
	if bootstrap.PublicKey != "" {
		env += "WAF_RULE_PUBLIC_KEY_FILE=/rule-public-key\n"
		args = append(args, "--mount", "type=bind,src="+filepath.Join(state, "rule-public-key")+",dst=/rule-public-key,readonly")
	}
	if a.Config.CACertificate != "" {
		if err = executorTrustedConfig(a.Config.CACertificate); err != nil {
			return err
		}
		env += "SSL_CERT_FILE=/management-ca.pem\n"
		caBytes, readErr := readBoundedFile(a.Config.CACertificate, 64<<10)
		if readErr != nil {
			return readErr
		}
		caCopy := filepath.Join(state, "management-ca.pem")
		if err = writeHostWafTrustFile(caCopy, caBytes); err != nil {
			return err
		}
		args = append(args, "--mount", "type=bind,src="+caCopy+",dst=/management-ca.pem,readonly")
	}
	if err = os.WriteFile(filepath.Join(state, "node.env"), []byte(env), 0600); err != nil {
		return err
	}
	args = append(args, p.Image)
	containerID, err := hostTool("docker", args...)
	if err != nil {
		return err
	}
	if !regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(containerID) {
		return errors.New("docker did not return an immutable container identity")
	}
	if err = writePrivate(filepath.Join(state, "container.json"), containerID); err != nil {
		return err
	}
	status := "FAILED"
	transaction := filepath.Join(state, "nginx")
	defer func() {
		reported = true
		if resultErr != nil {
			var tx nginxTransaction
			read(filepath.Join(transaction, "journal.json"), &tx)
			current, readErr := os.ReadFile(p.NginxConfig)
			if readErr == nil && contentDigest(current) == contentDigest(source) || p.BusinessMode == "NEW" && os.IsNotExist(readErr) {
				_, stopErr := hostTool("docker", "stop", containerID)
				resultErr = errors.Join(resultErr, stopErr)
			}
			if tx.Status == "ROLLED_BACK" {
				status = "ROLLED_BACK"
			}
		}
		report := map[string]any{"schema": p.Schema, "siteId": p.SiteID, "mode": p.Mode, "status": status, "updatedAt": time.Now().UTC().Format(time.RFC3339Nano), "transactionDir": transaction, "message": "Normal ingress and synthetic WAF detection verified"}
		if resultErr != nil {
			report["message"] = "Onboarding failed; inspect the local transaction and original configuration"
		}
		if saveErr := writePrivate(filepath.Join(state, "report.json"), report); saveErr != nil {
			resultErr = errors.Join(resultErr, errors.New("local onboarding report could not be persisted"))
		}
		if publishErr := a.request("POST", "/agent/network-report", a.Identity.Token, report, nil); publishErr != nil {
			resultErr = errors.Join(resultErr, errors.New("local outcome retained; platform report delivery failed"))
		}
		resultErr = errors.Join(resultErr, json.NewEncoder(out).Encode(report))
	}()
	// Ensure the loopback listener is serving before changing any nginx file.
	ready := false
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		conn, e := net.DialTimeout("tcp4", local, 100*time.Millisecond)
		if e == nil {
			conn.Close()
			ready = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !ready {
		return errors.New("WAF startup failed; nginx unchanged")
	}
	var nonce [12]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		return err
	}
	token := hex.EncodeToString(nonce[:])
	verify := func() error { return verifyHostWafIngress(wafState, p, before, token) }
	review := func() error {
		if p.ExpectedNginxSHA256 == "" {
			return nil
		}
		source, e := nginxPlanSource(p)
		if e != nil {
			return e
		}
		if p.BusinessMode == "NEW" {
			source = nil
		}
		dump, e := hostTool("nginx", "-T")
		if e != nil {
			return e
		}
		preview, e := describeNginxPreflight(p, source, []byte(dump))
		if e != nil {
			return e
		}
		if preview.NginxSHA256 != p.ExpectedNginxSHA256 || preview.ConfigSHA256 != p.ExpectedConfigSHA256 || preview.PlannedConfigSHA256 != p.ExpectedPlannedConfigSHA256 {
			return errors.New("nginx configuration changed during deployment; reviewed change not published")
		}
		return nil
	}
	if p.BusinessMode == "NEW" {
		err = applyNewNginxTransaction(p.NginxConfig, transaction, after, verify, runNginx, review)
	} else {
		err = applyNginxTransaction(p.NginxConfig, transaction, after, contentDigest(source), verify, runNginx, review)
	}
	if err != nil {
		return err
	}
	status = "VERIFIED"
	return nil
}

func finishInstallationHostWaf(installationID string, c Config, out io.Writer) error {
	a, err := hostNetworkAgent()
	if err != nil {
		return err
	}
	var response struct {
		Plan HostWafPlan `json:"plan"`
	}
	if err = a.request("POST", "/agent/host-waf/installation-plan", a.Identity.Token, map[string]string{"installationId": installationID}, &response); err != nil {
		return err
	}
	root := "/var/lib/selfguard-host-waf"
	if err = os.MkdirAll(root, 0700); err != nil {
		return err
	}
	if err = executorTrustedDirectory(root, true); err != nil {
		return err
	}
	path := filepath.Join(root, "install-"+installationID+".json")
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	err = json.NewEncoder(file).Encode(response.Plan)
	err = errors.Join(err, file.Sync(), file.Close())
	if err != nil {
		return err
	}
	return runHostWafOnboarding(path, out)
}

func runHostWafRollback(transaction string, out io.Writer) error {
	if err := executorPlatform(); err != nil {
		return err
	}
	state := filepath.Dir(transaction)
	if _, err := os.Lstat(filepath.Join(state, "plan.json")); err == nil {
		if err = executorTrustedConfig(filepath.Join(state, "plan.json")); err != nil {
			return err
		}
		raw, e := readBoundedFile(filepath.Join(state, "plan.json"), 16<<10)
		if e != nil {
			return e
		}
		var plan HostWafPlan
		if e = decodeExecutorParameters(raw, &plan); e != nil {
			return e
		}
		a, e := hostNetworkAgent()
		if e != nil {
			return e
		}
		if a.Identity.AssetID != plan.AssetID {
			return errors.New("rollback state belongs to another asset")
		}
		report, e := rollbackBoundNginxState(state, plan, runNginx)
		if e != nil {
			return e
		}
		return publishHostWafRollback(report, out)
	} else if !os.IsNotExist(err) {
		return err
	}

	if err := executorPlatform(); err != nil {
		return err
	}
	if err := executorTrustedDirectory(transaction, true); err != nil {
		return err
	}
	if err := rollbackNginxTransaction(transaction, runNginx); err != nil {
		return err
	}
	reportPath := filepath.Join(filepath.Dir(transaction), "report.json")
	if err := executorTrustedConfig(reportPath); err != nil {
		return err
	}
	b, err := readBoundedFile(reportPath, 16<<10)
	if err != nil {
		return err
	}
	var report map[string]any
	if err = json.Unmarshal(b, &report); err != nil {
		return err
	}
	report["status"] = "ROLLED_BACK"
	report["message"] = "Original nginx configuration restored and nginx reload accepted"
	report["updatedAt"] = time.Now().UTC().Format(time.RFC3339Nano)
	if err = writePrivate(reportPath, report); err != nil {
		return err
	}
	return publishHostWafRollback(report, out)
}
func publishHostWafRollback(report map[string]any, out io.Writer) error {
	a, err := hostNetworkAgent()
	if err != nil {
		return err
	}
	if err = a.request("POST", "/agent/network-report", a.Identity.Token, report, nil); err != nil {
		return errors.New("nginx restored locally; platform report unavailable, retry the same rollback to publish")
	}
	return json.NewEncoder(out).Encode(report)
}

// SSH jobs use umask 077. Public roots must still be readable by the unprivileged
// WAF process through its read-only bind mount; no private key is written here.
func writeHostWafTrustFile(path string, body []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, err = file.Write(body)
	if err == nil {
		err = file.Chmod(0644)
	}
	if err == nil {
		err = file.Sync()
	}
	err = errors.Join(err, file.Close())
	if err != nil {
		return err
	}
	return syncParent(path)
}
