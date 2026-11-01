package main

import (
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"
)

type Distribution struct {
	ID        string `json:"id"`
	VersionID string `json:"versionId"`
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
	return parseDistribution(f)
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
		if !ok || (key != "ID" && key != "VERSION_ID") {
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
	return d, PackageCollection{Complete: true, Reason: "collected"}
}
