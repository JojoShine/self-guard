package main

import (
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var managedStatePath = regexp.MustCompile(`^/var/lib/selfguard-agent(?:-[a-z0-9][a-z0-9-]{0,40})?$`)

func installationStateDir(value string) (string, error) {
	if value == "" {
		value = "/var/lib/selfguard-agent"
	}
	if !managedStatePath.MatchString(value) {
		return "", errors.New("state directory must be a dedicated /var/lib/selfguard-agent[-name] directory")
	}
	return value, nil
}
func validCollectionPath(value string) bool {
	return len(value) <= 1000 && value != "/" && filepath.IsAbs(value) && filepath.Clean(value) == value && regexp.MustCompile(`^/[A-Za-z0-9_./-]+$`).MatchString(value)
}
func installationProxy(value string) (*url.URL, error) {
	if value == "" {
		return nil, nil
	}
	u, err := url.Parse(value)
	if err != nil || len(value) > 2048 || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return nil, errors.New("proxy must be an HTTP(S) origin without credentials")
	}
	return u, nil
}
func applyInstallationProfile(c Config, p installationProfile) (Config, error) {
	var err error
	c.StateDir, err = installationStateDir(p.StateDir)
	if err != nil {
		return c, err
	}
	if _, err = installationProxy(p.ProxyURL); err != nil {
		return c, err
	}
	c.ProxyURL = p.ProxyURL
	c.ProxyMode = p.ProxyMode
	if c.ProxyMode == "" {
		c.ProxyMode = "DIRECT"
		if c.ProxyURL != "" {
			c.ProxyMode = "EXPLICIT"
		}
	}
	if (c.ProxyMode != "DIRECT" && c.ProxyMode != "EXPLICIT" && c.ProxyMode != "ENVIRONMENT") || (c.ProxyMode == "EXPLICIT") != (c.ProxyURL != "") {
		return c, errors.New("proxy mode and URL do not agree")
	}
	c.ReadOnly = true
	if p.CollectionRoot != "" && !validCollectionPath(p.CollectionRoot) {
		return c, errors.New("explicit non-root collection directory required")
	}
	if len(p.FIMPaths) > 100 || len(p.LogPaths) > 100 {
		return c, errors.New("collection path budget exceeded")
	}
	for _, path := range append(append([]string{}, p.FIMPaths...), p.LogPaths...) {
		if !validCollectionPath(path) || p.CollectionRoot == "" || !strings.HasPrefix(path, p.CollectionRoot+"/") {
			return c, errors.New("collection path outside authorized directory")
		}
	}
	if err = validateApplicationInputs(p.CollectionRoot, p.ApplicationInputs); err != nil {
		return c, err
	}
	c.ApplicationInputs = p.ApplicationInputs
	c.AllowedRoot = p.CollectionRoot
	c.FIMPaths = p.FIMPaths
	c.LogPaths = p.LogPaths
	c.LogIncludeMessage = p.LogIncludeMessage
	if p.MaxCPUs == 0 {
		p.MaxCPUs = 1
	}
	if p.MaxMemoryBytes == 0 {
		p.MaxMemoryBytes = 128 << 20
	}
	if p.MaxQueueBytes == 0 {
		p.MaxQueueBytes = 32 << 20
	}
	if p.BytesPerSecond == 0 {
		p.BytesPerSecond = 128 << 10
	}
	if p.CPUQuotaPercent == 0 {
		p.CPUQuotaPercent = 20
	}
	if p.MaxCPUs < 1 || p.MaxCPUs > 8 || p.MaxMemoryBytes < 64<<20 || p.MaxMemoryBytes > 1<<30 || p.MaxQueueBytes < 1<<20 || p.MaxQueueBytes > 512<<20 || p.BytesPerSecond < 1024 || p.BytesPerSecond > 10<<20 || p.CPUQuotaPercent < 1 || p.CPUQuotaPercent > 100 {
		return c, errors.New("installation resource budget outside allowed limits")
	}
	c.MaxCPUs = p.MaxCPUs
	c.MaxMemoryBytes = p.MaxMemoryBytes
	c.MaxQueueBytes = p.MaxQueueBytes
	c.BytesPerSecond = p.BytesPerSecond
	c.CPUQuotaPercent = p.CPUQuotaPercent
	return c, nil
}

// A different path must never silently generate a second identity on reinstall.
func existingInstallationState(state string) error {
	const file = "/etc/selfguard-agent/collector.json"
	if _, err := os.Lstat(file); err == nil {
		if err = executorTrustedConfig(file); err != nil {
			return err
		}
		var c Config
		if err = read(file, &c); err != nil {
			return err
		}
		if c.StateDir != state {
			return errors.New("existing installation uses another state directory; identity migration requires explicit recovery")
		}
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}
	if state != "/var/lib/selfguard-agent" {
		if _, err := os.Lstat("/var/lib/selfguard-agent/identity.json"); err == nil {
			return errors.New("existing default identity retained; refusing another state directory")
		} else if !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}
