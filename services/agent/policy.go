package main

import (
	"os"
	"path/filepath"
	"strings"
	"time"
)

type PolicyConfig struct {
	InstanceID    string            `json:"instanceId,omitempty"`
	Engines       []string          `json:"engines,omitempty"`
	Operations    []string          `json:"operations,omitempty"`
	Applicability RuleApplicability `json:"applicability,omitempty"`
	Exceptions    []RuleException   `json:"exceptions,omitempty"`
	Path          string            `json:"path"`
	Mode          string            `json:"mode"`
	Contains      string            `json:"contains"`
	Field         string            `json:"field"`
	Threshold     int               `json:"threshold"`
	WindowSeconds int               `json:"windowSeconds"`
	Type          string            `json:"type"`
	Key           string            `json:"key"`
	Value         string            `json:"value"`
	Service       string            `json:"service"`
	State         string            `json:"state"`
}
type PolicyRule struct {
	Name     string       `json:"name"`
	Severity string       `json:"severity"`
	ID       string       `json:"id"`
	Kind     string       `json:"kind"`
	Config   PolicyConfig `json:"config"`
}

func (a *Agent) applyPolicy(rules []PolicyRule) {
	a.applyPolicyForAssetAt(rules, PolicyAsset{ID: a.Identity.AssetID}, time.Now())
}
func (a *Agent) applyPolicyForAssetAt(rules []PolicyRule, asset PolicyAsset, now time.Time) {
	if asset.ID != a.Identity.AssetID {
		asset = PolicyAsset{ID: a.Identity.AssetID}
	}
	a.RemoteChecks = nil
	a.RemoteFIM = nil
	a.LogRules = nil
	a.PolicyFindings = nil
	count := 0
	for _, r := range rules {
		if !ruleApplies(r.Config, asset) || (r.Kind == "BASELINE" && baselineExempt(r.Config, asset, now)) {
			continue
		}
		if count >= 100 {
			break
		}
		count++
		switch r.Kind {
		case "BASELINE":
			if r.Config.Type == "DATABASE_SECURITY" || (r.Config.Type == "SERVICE_STATE" && validService(r.Config.Service)) || safePath(a.Config.AllowedRoot, r.Config.Path) == nil {
				a.RemoteChecks = append(a.RemoteChecks, Check{RuleID: r.ID, RuleName: r.Name, RuleSeverity: r.Severity, Type: r.Config.Type, Path: r.Config.Path, Mode: r.Config.Mode, Key: r.Config.Key, Value: r.Config.Value, Service: r.Config.Service, State: r.Config.State})
			}
		case "FIM":
			if safeWatchPath(a.Config.AllowedRoot, r.Config.Path) == nil {
				a.RemoteFIM = append(a.RemoteFIM, r.Config.Path)
			}
		case "LOG":
			if r.Config.Field == "" {
				r.Config.Field = "message"
			}
			if databaseLogRule(r.Config) {
				if safePath(a.Config.AllowedRoot, r.Config.Path) == nil && r.Config.Threshold >= 1 && r.Config.Threshold <= 1000 && r.Config.WindowSeconds >= 1 && r.Config.WindowSeconds <= 86400 && (r.Config.Service == "mysql" || r.Config.Service == "postgresql" || r.Config.Service == "audit-json") && (r.Config.Type != "DATABASE_CLEARTEXT" || r.Config.Service == "audit-json") && ((r.Config.Type != "DATABASE_ACTIVITY" && r.Config.Type != "DATABASE_ACCESS") || (r.Config.InstanceID != "" && r.Config.Service == "audit-json")) {
					a.LogRules = append(a.LogRules, r)
				} else {
					a.PolicyFindings = append(a.PolicyFindings, databaseCoverage(r, r.Config.Path, "规则路径未通过本地授权边界或规则参数不受支持；未执行读取"))
				}
				continue
			}
			if r.Config.Threshold <= 10000 && r.Config.WindowSeconds >= 0 && r.Config.WindowSeconds <= 86400 && r.Config.Contains != "" && len(r.Config.Contains) <= 1024 && (r.Config.Field == "message" || r.Config.Field == "source") {
				a.LogRules = append(a.LogRules, r)
			}
		}
	}
}
func (a *Agent) policy() {
	var snapshot struct {
		Rules           []PolicyRule `json:"rules"`
		DatabaseSources []struct {
			InstanceID string `json:"instanceId"`
			Engine     string `json:"engine"`
			Path       string `json:"path"`
			Service    string `json:"service"`
		} `json:"databaseSources"`
		Asset PolicyAsset `json:"asset"`
	}
	path := filepath.Join(a.Config.StateDir, "policy.json")
	if a.request("GET", "/agent/policy?capabilities=data-security-v1,data-security-v2", a.Identity.Token, nil, &snapshot) == nil {
		if writePrivate(path, snapshot) != nil {
			return
		}
	} else if read(path, &snapshot) != nil {
		return
	}
	a.applyPolicyForAssetAt(snapshot.Rules, snapshot.Asset, time.Now())
	for i, source := range snapshot.DatabaseSources {
		if i >= 20 {
			break
		}
		rule := PolicyRule{ID: "database-collection:" + source.InstanceID + ":" + source.Path, Config: PolicyConfig{Type: "DATABASE_COLLECTION", InstanceID: source.InstanceID, Path: source.Path, Service: source.Service, Engines: []string{source.Engine}}}
		if source.InstanceID != "" && safePath(a.Config.AllowedRoot, source.Path) == nil && databaseFormat(source.Service) {
   filtered:=a.LogRules[:0];for _,existing:=range a.LogRules{if existing.Config.InstanceID==source.InstanceID&&existing.Config.Path==source.Path{continue};filtered=append(filtered,existing)};a.LogRules=filtered
			a.LogRules = append(a.LogRules, rule)
		} else {
			a.PolicyFindings = append(a.PolicyFindings, databaseCoverage(rule, source.Path, "独立审计来源未通过本地采集授权"))
		}
	}

}
func matches(body, pattern string, threshold int) int {
	if threshold < 1 {
		threshold = 1
	}
	count := 0
	for _, line := range strings.Split(body, "\n") {
		if strings.Contains(line, pattern) {
			count++
		}
	}
	if count < threshold {
		return 0
	}
	return count
}

func packages() ([]Package, PackageCollection) {
	distribution, _ := distributionInventory("/etc/os-release")
	if distribution.ID == "alpine" {
		file, err := os.Open("/lib/apk/db/installed")
		if err != nil {
			return []Package{}, PackageCollection{Reason: "apk installed database unavailable"}
		}
		defer file.Close()
		return parseApkInstalled(file)
	}
	lines, status := packageInventory()
	return parsePackageMetadata(lines, status)
}

// Watch an absent file only when its existing parent is inside the authorized root.
func safeWatchPath(root, path string) error {
	err := safePath(root, path)
	if os.IsNotExist(err) {
		return safePath(root, filepath.Dir(path))
	}
	return err
}
