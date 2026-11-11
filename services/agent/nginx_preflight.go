package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

type NginxPreflight struct {
	CPUQuota            float64  `json:"cpuQuota,omitempty"`
	MemoryLimitBytes    int64    `json:"memoryLimitBytes,omitempty"`
	Schema              string   `json:"schema"`
	AssetID             string   `json:"assetId"`
	SiteID              string   `json:"siteId"`
	BusinessMode        string   `json:"businessMode"`
	Hostname            string   `json:"hostname"`
	NginxConfig         string   `json:"nginxConfig"`
	ConfigSHA256        string   `json:"configSha256"`
	NginxSHA256         string   `json:"nginxSha256"`
	PlannedConfigSHA256 string   `json:"plannedConfigSha256"`
	Changes             []string `json:"changes"`
	Preserved           []string `json:"preserved"`
}

func nginxPlanSource(p HostWafPlan) ([]byte, error) {
	if p.BusinessMode != "NEW" {
		if err := executorTrustedConfig(p.NginxConfig); err != nil {
			return nil, err
		}
		return readBoundedFile(p.NginxConfig, 256<<10)
	}
	if err := executorTrustedDirectory(filepath.Dir(p.NginxConfig), false); err != nil {
		return nil, err
	}
	if _, err := os.Lstat(p.NginxConfig); !os.IsNotExist(err) {
		return nil, errors.New("new nginx configuration path must not exist")
	}
	if p.CertificateFile != "" {
		if err := executorTrustedConfig(p.CertificateFile); err != nil {
			return nil, err
		}
		if err := executorTrustedConfig(p.CertificateKeyFile); err != nil {
			return nil, err
		}
		pair, err := tls.LoadX509KeyPair(p.CertificateFile, p.CertificateKeyFile)
		if err != nil || len(pair.Certificate) == 0 {
			return nil, errors.New("nginx certificate/key pair is invalid")
		}
		leaf, err := x509.ParseCertificate(pair.Certificate[0])
		if err != nil || leaf.VerifyHostname(p.Hostname) != nil || time.Now().Before(leaf.NotBefore) || !time.Now().Before(leaf.NotAfter) {
			return nil, errors.New("nginx certificate must match hostname and be currently valid")
		}
	}
	return newNginxSite(p)
}
func describeNginxPreflight(p HostWafPlan, source, dump []byte) (NginxPreflight, error) {
	if err := p.validate(); err != nil {
		return NginxPreflight{}, err
	}
	ds, err := nginxDirectives(dump)
	if err != nil {
		return NginxPreflight{}, errors.New("nginx full configuration requires manual review")
	}
	names, loaded, includeMatches := 0, false, 0
	for _, d := range ds {
		if d.name == "server_name" {
			for _, name := range d.args {
				if strings.EqualFold(name, p.Hostname) {
					names++
				}
			}
		}
		if d.name == "include" && len(d.args) == 1 {
			matched, e := filepath.Match(d.args[0], p.NginxConfig)
			if e == nil && matched {
				loaded = true
				includeMatches++
			}
		}
	}
	mode := "EXISTING"
	before := contentDigest(source)
	changes := []string{"将此站点业务上游改为本机WAF", "配置可信本机代理头", "Nginx配置检查与平滑加载", "正常业务及检测样本实际验证"}
	preserved := []string{"域名和监听入口", "现有证书配置", "其他站点配置"}
	if p.BusinessMode == "NEW" {
		mode = "NEW"
		before = "ABSENT"
		if names != 0 || !loaded || includeMatches != 1 || len(source) != 0 {
			return NginxPreflight{}, errors.New("new hostname must be unique and new file must match exactly one loaded include")
		}
		if err = preserveNginxDefault(p, dump, ds); err != nil {
			return NginxPreflight{}, err
		}
		source, err = newNginxSite(p)
		if err != nil {
			return NginxPreflight{}, err
		}
		changes = append([]string{"创建独立Nginx站点文件"}, changes...)
		preserved = []string{"所有原有站点配置", "主机上的证书及私钥文件"}
	} else if names != 1 || !strings.Contains(string(dump), "# configuration file "+p.NginxConfig+":") {
		return NginxPreflight{}, errors.New("selected nginx file must be loaded and hostname must be unique")
	}
	after, err := planNginxOnboarding(source, p.Hostname, p.Upstream, "127.0.0.1:"+strconv.Itoa(p.WafPort))
	if err != nil {
		return NginxPreflight{}, err
	}
	return NginxPreflight{CPUQuota: p.WafCPUQuota, MemoryLimitBytes: p.WafMemoryBytes, Schema: "selfguard-nginx-preflight-v1", AssetID: p.AssetID, SiteID: p.SiteID, BusinessMode: mode, Hostname: p.Hostname, NginxConfig: p.NginxConfig, ConfigSHA256: before, NginxSHA256: contentDigest(dump), PlannedConfigSHA256: contentDigest(after), Changes: changes, Preserved: preserved}, nil
}

// A wildcard vhost loaded before an implicit default changes unrelated Host routing.
// Only accept a shared, ordered include or an already explicit wildcard default.
func preserveNginxDefault(p HostWafPlan, dump []byte, ds []nginxDirective) error {
	headers := regexp.MustCompile(`(?m)^# configuration file ([^\r\n]+):\r?$`).FindAllSubmatchIndex(dump, -1)
	fileAt := func(offset int) string {
		name := ""
		for _, h := range headers {
			if h[0] > offset {
				break
			}
			name = string(dump[h[2]:h[3]])
		}
		return name
	}
	var listeners []nginxDirective
	for i, d := range ds {
		if d.name != "server{" {
			continue
		}
		found := false
		for _, child := range ds[i+1:] {
			if child.depth <= d.depth {
				break
			}
			if child.name == "listen" && child.depth == d.depth+1 {
				found = true
				listeners = append(listeners, child)
			}
		}
		if !found {
			listeners = append(listeners, nginxDirective{args: []string{"80"}, start: d.start})
		}
	}
	var implicit []nginxDirective
	for _, d := range listeners {
		if len(d.args) == 0 {
			return errors.New("nginx listen requires manual review")
		}
		address := d.args[0]
		port := address
		if colon := strings.LastIndexByte(address, ':'); colon >= 0 {
			port = address[colon+1:]
		}
		if port != strconv.Itoa(p.ListenPort) {
			continue
		}
		wildcard := address == port || address == "*:"+port || address == "0.0.0.0:"+port
		if !wildcard {
			return errors.New("address-specific nginx listeners require manual review before adding a wildcard listener")
		}
		for _, arg := range d.args[1:] {
			if arg == "default_server" {
				return nil
			}
		}
		implicit = append(implicit, d)
	}
	for _, listener := range implicit {
		old := fileAt(listener.start)
		ordered := false
		for _, d := range ds {
			if d.name != "include" || len(d.args) != 1 {
				continue
			}
			pattern := d.args[0]
			oldMatch, e1 := filepath.Match(pattern, old)
			newMatch, e2 := filepath.Match(pattern, p.NginxConfig)
			if e1 == nil && e2 == nil && oldMatch && newMatch && filepath.Dir(pattern) == filepath.Dir(old) && filepath.Dir(old) == filepath.Dir(p.NginxConfig) && old < p.NginxConfig {
				ordered = true
			}
		}
		if !ordered {
			return errors.New("new nginx file may replace an existing implicit default; use a later filename in the same include or explicitly preserve the existing default first")
		}
	}
	return nil
}
func inspectNginxPlan(p HostWafPlan) (NginxPreflight, error) {
	if err := p.validate(); err != nil {
		return NginxPreflight{}, err
	}
	source, err := nginxPlanSource(p)
	if err != nil {
		return NginxPreflight{}, err
	}
	if p.BusinessMode == "NEW" {
		source = nil
	}
	dump, err := hostTool("nginx", "-T")
	if err != nil {
		return NginxPreflight{}, err
	}
	preview, err := describeNginxPreflight(p, source, []byte(dump))
	if err != nil {
		return NginxPreflight{}, err
	}
	image, err := hostTool("docker", "image", "inspect", "--format", "{{.Os}}|{{.Architecture}}", p.Image)
	if err != nil {
		if p.ImageArchiveSHA256 == "" || p.ImageArchiveBytes < 1 {
			return NginxPreflight{}, errors.New("WAF image is not available on the host or from approved platform delivery")
		}
		preview.Changes = append([]string{"下载并核验平台固定WAF镜像"}, preview.Changes...)
	} else if image != "linux|"+runtime.GOARCH {
		return NginxPreflight{}, errors.New("WAF image architecture differs from this host")
	}
	return preview, nil
}
func readHostWafPlan(path string) (HostWafPlan, error) {
	var p HostWafPlan
	if err := executorPlatform(); err != nil {
		return p, err
	}
	if err := executorTrustedConfig(path); err != nil {
		return p, err
	}
	b, err := readBoundedFile(path, 16<<10)
	if err != nil {
		return p, err
	}
	if err = decodeExecutorParameters(b, &p); err != nil {
		return p, err
	}
	return p, p.validate()
}
func runNginxPreflight(path string, out io.Writer) error {
	p, err := readHostWafPlan(path)
	if err != nil {
		return err
	}
	a, err := hostNetworkAgent()
	if err != nil {
		return err
	}
	if a.Identity.AssetID != p.AssetID {
		return errors.New("nginx plan belongs to another asset")
	}
	preview, err := inspectNginxPlan(p)
	if err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(preview)
}

func probeBusinessUpstream(p HostWafPlan) (ingressProbe, error) {
	target := p.Upstream + p.HealthPath
	req, err := http.NewRequest("GET", target, nil)
	if err != nil {
		return ingressProbe{}, err
	}
	req.Host = p.Hostname
	client := &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }, Transport: &http.Transport{Proxy: nil}}
	response, err := client.Do(req)
	if err != nil {
		return ingressProbe{}, errors.New("new business upstream health probe failed")
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 65537))
	if err != nil || len(body) > 65536 {
		return ingressProbe{}, errors.New("new business health response exceeds budget")
	}
	return ingressProbe{status: response.StatusCode, body: body, target: p.HealthPath}, nil
}

func runNginxPlanRollback(path string, out io.Writer) error {
	p, err := readHostWafPlan(path)
	if err != nil {
		return err
	}
	a, err := hostNetworkAgent()
	if err != nil {
		return err
	}
	if a.Identity.AssetID != p.AssetID {
		return errors.New("rollback plan belongs to another asset")
	}
	root := filepath.Join("/var/lib/selfguard-host-waf", p.AssetID)
	report, err := rollbackBoundNginxState(root, p, runNginx)
	if err != nil {
		return err
	}
	return publishHostWafRollback(report, out)
}
