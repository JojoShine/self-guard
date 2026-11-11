package main

import (
	"archive/zip"
	"bufio"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"regexp"
	"runtime/debug"
	"strings"
	"syscall"
	"unicode/utf8"
)

const maxArchiveBytes int64 = 256 << 20
const maxEntryBytes int64 = 2 << 20

// Current official Ubuntu USN records exceed 4MiB; other ecosystem budgets stay unchanged.
const ubuntuEntryBytes int64 = 8 << 20
const maxDecodedBytes uint64 = 4 << 30

var recordFilename = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:+-]{0,199}\.json$`)

type archiveProfile struct {
	archiveBytes, entryBytes int64
	decodedBytes             uint64
	ubuntuRelease            string
	versionsOnly             bool
}

func readArchive(filename, expected string, output io.Writer) error {
	return readArchiveProfile(filename, expected, output, archiveProfile{archiveBytes: maxArchiveBytes, entryBytes: maxEntryBytes, decodedBytes: maxDecodedBytes})
}
func readUbuntuArchive(filename, expected string, output io.Writer, release string) error {
	if release != "22.04" && release != "24.04" {
		return errors.New("unsupported Ubuntu archive release")
	}
	return readArchiveProfile(filename, expected, output, archiveProfile{archiveBytes: 1 << 30, entryBytes: ubuntuEntryBytes, decodedBytes: 12 << 30, ubuntuRelease: release})
}
func readArchiveVersions(filename, expected string, output io.Writer, ubuntu bool) error {
	profile := archiveProfile{archiveBytes: maxArchiveBytes, entryBytes: maxEntryBytes, decodedBytes: maxDecodedBytes, versionsOnly: true}
	if ubuntu {
		profile.archiveBytes, profile.entryBytes, profile.decodedBytes = 1<<30, ubuntuEntryBytes, 12<<30
	}
	return readArchiveProfile(filename, expected, output, profile)
}
func readArchiveProfile(filename, expected string, output io.Writer, profile archiveProfile) error {
	if len(expected) != 64 {
		return errors.New("canonical archive SHA256 required")
	}
	if _, err := hex.DecodeString(expected); err != nil {
		return errors.New("invalid archive SHA256")
	}
	file, err := os.Open(filename)
	if err != nil {
		return errors.New("archive file unavailable")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > profile.archiveBytes {
		return errors.New("archive file exceeds regular-file budget")
	}
	hash := sha256.New()
	transportCRC := crc32.New(crc32.MakeTable(crc32.Castagnoli))
	if _, err = io.Copy(io.MultiWriter(hash, transportCRC), file); err != nil {
		return errors.New("archive read failed")
	}
	actual := hex.EncodeToString(hash.Sum(nil))
	if actual != strings.ToLower(expected) {
		return errors.New("archive SHA256 mismatch")
	}
	archive, err := zip.NewReader(file, info.Size())
	if err != nil {
		return errors.New("invalid or truncated ZIP directory")
	}
	if len(archive.File) < 1 || len(archive.File) > 1000000 {
		return errors.New("archive entry count outside budget")
	}
	seen := map[string]bool{}
	var total uint64
	for _, entry := range archive.File {
		if !recordFilename.MatchString(entry.Name) || entry.Mode()&os.ModeType != 0 || entry.Flags&1 != 0 || seen[entry.Name] {
			return errors.New("unsafe, duplicate or non-record archive entry")
		}
		seen[entry.Name] = true
		if entry.UncompressedSize64 > uint64(profile.entryBytes) {
			return errors.New("archive entry exceeds profile budget")
		}
		total += entry.UncompressedSize64
		if total > profile.decodedBytes {
			return errors.New("archive decoded bytes exceed profile budget")
		}
	}
	writer := bufio.NewWriterSize(output, 64<<10)
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(false)
	emitted := 0
	for _, entry := range archive.File {
		reader, err := entry.Open()
		if err != nil {
			return errors.New("archive compression method unsupported or entry invalid")
		}
		data, readErr := io.ReadAll(io.LimitReader(reader, profile.entryBytes+1))
		closeErr := reader.Close()
		if readErr != nil || closeErr != nil {
			return errors.New("archive entry CRC or decompression failed")
		}
		if int64(len(data)) > profile.entryBytes || uint64(len(data)) != entry.UncompressedSize64 || !utf8.Valid(data) || !json.Valid(data) {
			return errors.New("archive entry size, UTF8 or JSON invalid")
		}
		var identity struct {
			ID       string `json:"id"`
			Modified string `json:"modified"`
		}
		eligible := true
		var decodeErr error
		if profile.ubuntuRelease != "" {
			var scoped struct {
				ID       string `json:"id"`
				Affected []struct {
					Package *struct {
						Ecosystem string `json:"ecosystem"`
					} `json:"package"`
				} `json:"affected"`
			}
			decodeErr = json.Unmarshal(data, &scoped)
			identity.ID = scoped.ID
			eligible = false
			for _, affected := range scoped.Affected {
				if affected.Package == nil || affected.Package.Ecosystem == "Ubuntu:"+profile.ubuntuRelease+":LTS" || affected.Package.Ecosystem == "Ubuntu:"+profile.ubuntuRelease {
					eligible = true
				}
			}
		} else {
			decodeErr = json.Unmarshal(data, &identity)
		}
		if decodeErr != nil || identity.ID != strings.TrimSuffix(entry.Name, ".json") {
			return errors.New("archive record identity or scope invalid")
		}
		if !eligible {
			continue
		}
		emitted++
		if profile.versionsOnly {
			if identity.Modified == "" || len(identity.Modified) > 100 {
				return errors.New("archive original modification time unavailable")
			}
			if err := encoder.Encode(struct {
				Kind     string `json:"kind"`
				ID       string `json:"id"`
				Modified string `json:"modified"`
			}{"version", identity.ID, identity.Modified}); err != nil {
				return errors.New("archive version transport failed")
			}
			continue
		}
		if err := encoder.Encode(struct {
			Kind     string          `json:"kind"`
			Name     string          `json:"name"`
			Document json.RawMessage `json:"document"`
		}{"record", entry.Name, json.RawMessage(data)}); err != nil {
			return errors.New("archive record transport failed")
		}
	}
	var crcBytes [4]byte
	binary.BigEndian.PutUint32(crcBytes[:], transportCRC.Sum32())
	if err := encoder.Encode(struct {
		Kind           string `json:"kind"`
		Entries        int    `json:"entries"`
		EmittedEntries int    `json:"emittedEntries"`
		DecodedBytes   uint64 `json:"decodedBytes"`
		SHA256         string `json:"sha256"`
		CRC32C         string `json:"crc32c"`
	}{"complete", len(archive.File), emitted, total, actual, base64.StdEncoding.EncodeToString(crcBytes[:])}); err != nil {
		return errors.New("archive completion transport failed")
	}
	return writer.Flush()
}
func main() {
	debug.SetMemoryLimit(512 << 20)
	release := ""
	versions, ubuntuVersions := false, false
	probeTemplates := len(os.Args) == 4 && os.Args[3] == "--probe-templates"
	if len(os.Args) == 5 && os.Args[3] == "--ubuntu" && (os.Args[4] == "22.04" || os.Args[4] == "24.04") {
		release = os.Args[4]
	} else if len(os.Args) == 4 && (os.Args[3] == "--versions" || os.Args[3] == "--versions-ubuntu") {
		versions, ubuntuVersions = true, os.Args[3] == "--versions-ubuntu"
	} else if len(os.Args) != 3 && !probeTemplates {
		fmt.Fprintln(os.Stderr, "usage: selfguard-intelligence-unzip ZIP_PATH SHA256 [--ubuntu 22.04|24.04 | --versions | --versions-ubuntu]")
		os.Exit(1)
	}
	cpu := uint64(300)
	if release != "" || ubuntuVersions {
		cpu = 900
	}
	if err := syscall.Setrlimit(syscall.RLIMIT_CPU, &syscall.Rlimit{Cur: cpu, Max: cpu + 1}); err != nil {
		fmt.Fprintln(os.Stderr, "archive CPU limits unavailable")
		os.Exit(1)
	}
	var err error
	if probeTemplates {
		err = readProbeArchive(os.Args[1], os.Args[2], os.Stdout)
	} else if versions {
		err = readArchiveVersions(os.Args[1], os.Args[2], os.Stdout, ubuntuVersions)
	} else if release != "" {
		err = readUbuntuArchive(os.Args[1], os.Args[2], os.Stdout, release)
	} else {
		err = readArchive(os.Args[1], os.Args[2], os.Stdout)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
