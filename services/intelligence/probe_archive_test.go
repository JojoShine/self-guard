package main

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func probeZip(t *testing.T, entries map[string]string) (string, string) {
	t.Helper()
	var b bytes.Buffer
	w := zip.NewWriter(&b)
	for name, data := range entries {
		f, e := w.Create(name)
		if e != nil {
			t.Fatal(e)
		}
		f.Write([]byte(data))
	}
	w.Close()
	p := filepath.Join(t.TempDir(), "rules.zip")
	os.WriteFile(p, b.Bytes(), 0600)
	return p, fmt.Sprintf("%x", sha256.Sum256(b.Bytes()))
}
func TestProbeArchiveCompleteAndRejectUnsafe(t *testing.T) {
	p, h := probeZip(t, map[string]string{"nuclei-templates-1/LICENSE.md": "MIT license", "nuclei-templates-1/http/cves/x.yaml": "id: x\n", "nuclei-templates-1/code/x.yaml": "id: unsupported\n"})
	var out bytes.Buffer
	if e := readProbeArchive(p, h, &out); e != nil {
		t.Fatal(e)
	}
	if strings.Count(out.String(), `"kind":"template"`) != 2 || !strings.Contains(out.String(), `"kind":"complete"`) {
		t.Fatal(out.String())
	}
	for _, name := range []string{"../escape.yaml", "repo/../escape.yaml", "/escape.yaml", "repo/link\\escape.yaml"} {
		p, h = probeZip(t, map[string]string{name: "x"})
		if readProbeArchive(p, h, &bytes.Buffer{}) == nil {
			t.Fatalf("accepted %s", name)
		}
	}
	if readProbeArchive(p, strings.Repeat("0", 64), &bytes.Buffer{}) == nil {
		t.Fatal("accepted wrong hash")
	}
}

func TestProbeArchiveRejectsCorruptionAndTruncation(t *testing.T) {
	p, _ := probeZip(t, map[string]string{"repo/LICENSE.md": "MIT", "repo/test.yaml": "id: fixture\n"})
	data, e := os.ReadFile(p)
	if e != nil {
		t.Fatal(e)
	}
	archive, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	offset, err := archive.File[0].DataOffset()
	if err != nil {
		t.Fatal(err)
	}
	for _, content := range [][]byte{data[:len(data)-8], append([]byte{}, data...)} {
		if len(content) == len(data) {
			content[offset] ^= 0xFF
		}
		file := filepath.Join(t.TempDir(), "bad.zip")
		os.WriteFile(file, content, 0600)
		digest := fmt.Sprintf("%x", sha256.Sum256(content))
		if readProbeArchive(file, digest, io.Discard) == nil {
			t.Fatal("accepted malformed ZIP")
		}
	}
}
