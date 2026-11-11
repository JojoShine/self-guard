package main

import (
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

type Distribution struct {
	ID           string `json:"id"`
	VersionID    string `json:"versionId"`
	Name         string `json:"name,omitempty"`
	Version      string `json:"version,omitempty"`
	KylinRelease string `json:"kylinRelease,omitempty"`
}

var distributionID = regexp.MustCompile(`^[a-z0-9._-]{1,128}$`)
var distributionVersion = regexp.MustCompile(`^[A-Za-z0-9._+-]{1,128}$`)

// os-release is data: never source it through a shell or execute expansions.
func distributionInventory(path string) (Distribution, PackageCollection) {
	f, err := os.Open(path)
	if err != nil {
		return Distribution{}, PackageCollection{Reason: "os-release unavailable"}
	}
	defer f.Close()
	d, status := parseDistribution(f)
	if status.Complete && d.ID == "kylin" {
		return kylinDistribution(d, filepath.Join(filepath.Dir(path), ".kyinfo"))
	}
	return d, status
}
func parseDistribution(r io.Reader) (Distribution, PackageCollection) {
	b, err := io.ReadAll(io.LimitReader(r, (64<<10)+1))
	if err != nil {
		return Distribution{}, PackageCollection{Reason: "os-release read failed"}
	}
	if len(b) > 64<<10 {
		return Distribution{}, PackageCollection{Reason: "os-release size limit exceeded"}
	}
	values := map[string]string{}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok || (key != "ID" && key != "VERSION_ID" && key != "NAME" && key != "VERSION") {
			continue
		}
		if _, exists := values[key]; exists {
			return Distribution{}, PackageCollection{Reason: "duplicate distribution field"}
		}
		value = strings.TrimSpace(value)
		if strings.HasPrefix(value, `"`) {
			value, err = strconv.Unquote(value)
			if err != nil {
				return Distribution{}, PackageCollection{Reason: "malformed distribution field"}
			}
		} else if strings.HasPrefix(value, "'") {
			if len(value) < 2 || !strings.HasSuffix(value, "'") {
				return Distribution{}, PackageCollection{Reason: "malformed distribution field"}
			}
			value = value[1 : len(value)-1]
		}
		values[key] = value
	}
	d := Distribution{ID: strings.ToLower(values["ID"]), VersionID: values["VERSION_ID"]}
	if !distributionID.MatchString(d.ID) || !distributionVersion.MatchString(d.VersionID) {
		return Distribution{}, PackageCollection{Reason: "distribution ID or version missing or invalid"}
	}
	if d.ID == "kylin" {
		d.Name = values["NAME"]
		d.Version = values["VERSION"]
		if len(d.Name) > 256 || len(d.Version) > 256 {
			return Distribution{}, PackageCollection{Reason: "Kylin product metadata exceeds bound"}
		}
	}
	return d, PackageCollection{Complete: true, Reason: "collected"}
}

var kylinMilestone = regexp.MustCompile(`(?i)^(?:V)?10[-_]?SP([123])(?:[-_](2303|2403))?(?:[-_](?:Release|Build)[A-Za-z0-9._-]*)?$`)

func kylinDistribution(d Distribution, path string) (Distribution, PackageCollection) {
	failure := func(reason string) (Distribution, PackageCollection) {
		d.KylinRelease = ""
		return d, PackageCollection{Reason: reason}
	}
	f, err := os.Open(path)
	if err != nil {
		return failure("Kylin SP identity unavailable; verify /etc/.kyinfo")
	}
	defer f.Close()
	body, err := io.ReadAll(io.LimitReader(f, (64<<10)+1))
	if err != nil || len(body) > 64<<10 {
		return failure("Kylin identity unreadable or over limit")
	}
	section := ""
	values := map[string]string{}
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.ToLower(line[1 : len(line)-1])
			continue
		}
		if section != "dist" || line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		key = strings.TrimSpace(key)
		if !ok || (key != "name" && key != "milestone") {
			continue
		}
		if _, exists := values[key]; exists {
			return failure("duplicate Kylin identity field")
		}
		value = strings.TrimSpace(value)
		if len(value) > 256 {
			return failure("Kylin identity field exceeds bound")
		}
		values[key] = value
	}
	if !strings.EqualFold(values["name"], "Kylin-Server") || strings.Contains(strings.ToLower(d.Name), "desktop") || strings.Contains(d.Name, "桌面") {
		return failure("Kylin product is not the supported advanced server")
	}
	match := kylinMilestone.FindStringSubmatch(values["milestone"])
	if match == nil {
		return failure("Kylin SP or special edition is not identified")
	}
	branch := "V10SP" + match[1]
	if match[2] == "2403" {
		if match[1] != "3" {
			return failure("Kylin special edition is not identified")
		}
		branch += "-2403"
	}
	if !strings.Contains(strings.ToLower(d.Name), "server") && !strings.Contains(d.Name, "高级服务器") {
		d.Name = values["name"]
	}
	d.KylinRelease = branch
	return d, PackageCollection{Complete: true, Reason: "Kylin server product and SP collected"}
}
