package main

import (
	"archive/zip"
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path"
	"strings"
	"unicode/utf8"
)

// Validate every ZIP member, including non-template files, before accepting the snapshot.
func readProbeArchive(filename, expected string, output io.Writer) error {
	if len(expected) != 64 {
		return errors.New("canonical archive SHA256 required")
	}
	if _, err := hex.DecodeString(expected); err != nil {
		return err
	}
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > 512<<20 {
		return errors.New("probe archive size or type invalid")
	}
	hash := sha256.New()
	if _, err = io.Copy(hash, file); err != nil {
		return err
	}
	actual := hex.EncodeToString(hash.Sum(nil))
	if actual != expected {
		return errors.New("probe archive SHA256 mismatch")
	}
	archive, err := zip.NewReader(file, info.Size())
	if err != nil {
		return err
	}
	if len(archive.File) < 1 || len(archive.File) > 100000 {
		return errors.New("probe archive count exceeds budget")
	}
	seen := map[string]bool{}
	root := ""
	var total uint64
	for _, entry := range archive.File {
		name := strings.TrimSuffix(entry.Name, "/")
		parts := strings.Split(name, "/")
		if name == "" || strings.ContainsAny(name, "\\\x00\r\n") || path.IsAbs(name) || path.Clean(name) != name || len(parts) < 1 || parts[0] == ".." || seen[entry.Name] || entry.Flags&1 != 0 {
			return errors.New("unsafe or duplicate probe archive path")
		}
		if root == "" {
			root = parts[0]
		}
		if parts[0] != root {
			return errors.New("probe archive requires one root")
		}
		seen[entry.Name] = true
		if entry.Mode()&os.ModeType != 0 && !entry.FileInfo().IsDir() {
			return errors.New("probe archive nonregular member")
		}
		if entry.UncompressedSize64 > 16<<20 {
			return errors.New("probe archive entry exceeds budget")
		}
		total += entry.UncompressedSize64
		if total > 2<<30 {
			return errors.New("probe archive decoded budget exceeded")
		}
	}
	writer := bufio.NewWriter(output)
	enc := json.NewEncoder(writer)
	emitted := 0
	licenses := 0
	for _, entry := range archive.File {
		reader, err := entry.Open()
		if err != nil {
			return err
		}
		data, readErr := io.ReadAll(io.LimitReader(reader, 16<<20+1))
		closeErr := reader.Close()
		if readErr != nil || closeErr != nil || uint64(len(data)) != entry.UncompressedSize64 {
			return errors.New("probe archive CRC, size or decompression failed")
		}
		relative := strings.TrimPrefix(entry.Name, root+"/")
		kind := ""
		if strings.HasSuffix(relative, ".yaml") || strings.HasSuffix(relative, ".yml") {
			kind = "template"
			emitted++
		}
		if relative == "LICENSE.md" || relative == "LICENSE" {
			kind = "license"
			licenses++
		}
		if kind != "" {
			if !utf8.Valid(data) {
				return errors.New("probe archive UTF8 invalid")
			}
			if err = enc.Encode(struct {
				Kind string `json:"kind"`
				Name string `json:"name"`
				Raw  string `json:"raw"`
			}{kind, relative, string(data)}); err != nil {
				return err
			}
		}
	}
	if emitted == 0 || licenses != 1 {
		return errors.New("probe archive missing templates or unique license")
	}
	if err = enc.Encode(struct {
		Kind           string `json:"kind"`
		Entries        int    `json:"entries"`
		EmittedEntries int    `json:"emittedEntries"`
		DecodedBytes   uint64 `json:"decodedBytes"`
		SHA256         string `json:"sha256"`
	}{"complete", len(archive.File), emitted, total, actual}); err != nil {
		return err
	}
	return writer.Flush()
}
