package main

import (
	"bufio"
	"io"
	"regexp"
	"strings"
)

type Package struct {
	Name           string `json:"name"`
	Version        string `json:"version"`
	Origin         string `json:"origin,omitempty"`
	SourceVersion  string `json:"sourceVersion,omitempty"`
	SourceArtifact string `json:"sourceArtifact,omitempty"`
	Architecture   string `json:"architecture,omitempty"`
	Manager        string `json:"manager,omitempty"`
	Epoch          string `json:"epoch,omitempty"`
}

var packageIdentifier = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9+_.:-]{0,499}$`)
var packageVersion = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9+_.:~^!-]*$`)

func validPackageVersion(value string) bool {
	return len(value) <= 4096 && packageVersion.MatchString(value)
}

var packageEpoch = regexp.MustCompile(`^[0-9]+$`)
var rpmSigningKeyVersion = regexp.MustCompile(`^0:[0-9a-f]{8}-[0-9a-f]{8}$`)

func parsePackageMetadata(lines []string, status PackageCollection) ([]Package, PackageCollection) {
	out := []Package{}
	seen := map[string]bool{}
	for _, line := range lines {
		fields := strings.Split(line, "\t")
		if len(fields) < 6 {
			status = PackageCollection{Reason: "package source metadata missing"}
			continue
		}
		if fields[5] == "dpkg" && (len(fields) != 7 || fields[6] != "installed") {
			if len(fields) == 7 {
				continue
			}
			status = PackageCollection{Reason: "package installation state missing"}
			continue
		}
		// RPM 4.x stores imported signing keys as pseudo-packages, without an
		// architecture or source RPM. They are trust records, not installed software.
		if len(fields) == 6 && fields[5] == "rpm" && fields[0] == "gpg-pubkey" && fields[2] == "(none)" && fields[3] == "" && fields[4] == "(none)" && rpmSigningKeyVersion.MatchString(fields[1]) {
			continue
		}
		p := Package{Name: fields[0], Version: fields[1], Origin: fields[2], SourceVersion: fields[3], Architecture: fields[4], Manager: fields[5]}
		if !packageIdentifier.MatchString(p.Name) || !validPackageVersion(p.Version) || !packageIdentifier.MatchString(p.Architecture) {
			status = PackageCollection{Reason: "malformed package metadata"}
			continue
		}
		switch p.Manager {
		case "dpkg":
			if !packageIdentifier.MatchString(p.Origin) || !validPackageVersion(p.SourceVersion) {
				status = PackageCollection{Reason: "dpkg source package metadata missing"}
				continue
			}
		case "rpm":
			epoch, _, ok := strings.Cut(p.Version, ":")
			if !ok || !packageEpoch.MatchString(epoch) {
				status = PackageCollection{Reason: "rpm epoch missing"}
				continue
			}
			p.Epoch = epoch
			p.SourceArtifact = p.Origin
			p.Origin = ""
			p.SourceVersion = ""
			for _, suffix := range []string{".src.rpm", ".nosrc.rpm"} {
				if strings.HasSuffix(p.SourceArtifact, suffix) {
					base := strings.TrimSuffix(p.SourceArtifact, suffix)
					for i := 0; i < 2; i++ {
						at := strings.LastIndex(base, "-")
						if at < 1 {
							base = ""
							break
						}
						base = base[:at]
					}
					if packageIdentifier.MatchString(base) {
						p.Origin = base
					}
					break
				}
			}
		default:
			status = PackageCollection{Reason: "unknown package manager metadata"}
			continue
		}
		identity := p.Name + "\t" + p.Architecture + "\t" + p.Version
		if seen[identity] {
			status = PackageCollection{Reason: "duplicate package metadata"}
			continue
		}
		seen[identity] = true
		out = append(out, p)
	}
	return out, status
}

// The installed APK database is metadata, never a shell script. File lists and
// maintainer scripts are ignored; only the four package identity fields are read.
func parseApkInstalled(reader io.Reader) ([]Package, PackageCollection) {
	const limit = 16 << 20
	limited := &io.LimitedReader{R: reader, N: limit + 1}
	scanner := bufio.NewScanner(limited)
	scanner.Buffer(make([]byte, 4096), 65536)
	out := []Package{}
	status := PackageCollection{Complete: true, Reason: "collected"}
	fields := map[string]string{}
	seen := map[string]bool{}
	flush := func() {
		if len(fields) == 0 {
			return
		}
		p := Package{Name: fields["P"], Version: fields["V"], Origin: fields["o"], SourceVersion: fields["V"], Architecture: fields["A"], Manager: "apk"}
		fields = map[string]string{}
		if !packageIdentifier.MatchString(p.Name) || !validPackageVersion(p.Version) || !packageIdentifier.MatchString(p.Origin) || !packageIdentifier.MatchString(p.Architecture) {
			status = PackageCollection{Reason: "apk package identity incomplete"}
			return
		}
		key := p.Name + "\t" + p.Architecture
		if seen[key] {
			status = PackageCollection{Reason: "duplicate apk package identity"}
			return
		}
		seen[key] = true
		out = append(out, p)
	}
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			flush()
			if len(out) > 2000 {
				out = out[:2000]
				status = PackageCollection{Reason: "package count limit exceeded"}
				break
			}
			continue
		}
		if len(line) < 2 || line[1] != ':' {
			status = PackageCollection{Reason: "malformed apk metadata"}
			continue
		}
		key := line[:1]
		if key != "P" && key != "V" && key != "A" && key != "o" {
			continue
		}
		if _, exists := fields[key]; exists {
			status = PackageCollection{Reason: "duplicate apk identity field"}
		}
		fields[key] = line[2:]
	}
	flush()
	if scanner.Err() != nil {
		status = PackageCollection{Reason: "apk metadata read failed"}
	}
	if limited.N <= 0 {
		status = PackageCollection{Reason: "apk database size limit exceeded"}
	}
	if len(out) > 2000 {
		out = out[:2000]
		status = PackageCollection{Reason: "package count limit exceeded"}
	}
	return out, status
}
