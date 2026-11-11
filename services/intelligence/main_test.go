package main

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

type fixtureEntry struct {
	name, body string
	mode       os.FileMode
}

func archiveFixture(t *testing.T, entries ...fixtureEntry) (string, []byte) {
	t.Helper()
	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	for _, entry := range entries {
		header := &zip.FileHeader{Name: entry.name, Method: zip.Store}
		if entry.mode != 0 {
			header.SetMode(entry.mode)
		}
		file, err := writer.CreateHeader(header)
		if err != nil {
			t.Fatal(err)
		}
		file.Write([]byte(entry.body))
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	name := filepath.Join(t.TempDir(), "source.zip")
	data := buffer.Bytes()
	if err := os.WriteFile(name, data, 0600); err != nil {
		t.Fatal(err)
	}
	return name, data
}
func digest(data []byte) string { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }
func TestArchiveReaderValidatesAllRecordsBeforeItsCompletionMarker(t *testing.T) {
	file, data := archiveFixture(t, fixtureEntry{"GO-2026-0001.json", `{"id":"GO-2026-0001","details":"合法中文"}`, 0}, fixtureEntry{"GO-2026-0002.json", `{"id":"GO-2026-0002"}`, 0})
	var out bytes.Buffer
	if err := readArchive(file, digest(data), &out); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 3 {
		t.Fatal(out.String())
	}
	for _, line := range lines {
		if !json.Valid([]byte(line)) {
			t.Fatal(line)
		}
	}
	if !strings.Contains(lines[2], `"kind":"complete"`) {
		t.Fatal(out.String())
	}
	if err := readArchive(file, strings.Repeat("f", 64), &bytes.Buffer{}); err == nil {
		t.Fatal("source digest mismatch accepted")
	}
}
func TestArchiveReaderRefusesTraversalDuplicatesSymlinksAndIdentityConfusion(t *testing.T) {
	for _, entries := range [][]fixtureEntry{
		{{"../GO-2026-0001.json", `{"id":"GO-2026-0001"}`, 0}},
		{{"GO-2026-0001.json", `{"id":"GO-2026-0001"}`, 0}, {"GO-2026-0001.json", `{"id":"GO-2026-0001"}`, 0}},
		{{"GO-2026-0001.json", `{"id":"GO-2026-0001"}`, os.ModeSymlink | 0777}},
		{{"GO-2026-0001.json", `{"id":"DIFFERENT"}`, 0}},
		{{"GO-2026-0001.json", "{\"id\":\"GO-2026-0001\",\"details\":\"\xff\"}", 0}},
	} {
		file, data := archiveFixture(t, entries...)
		var out bytes.Buffer
		if err := readArchive(file, digest(data), &out); err == nil {
			t.Fatal("invalid archive accepted")
		}
		if strings.Contains(out.String(), `"kind":"complete"`) {
			t.Fatal("partial archive marked complete")
		}
	}
}
func TestArchiveReaderChecksCRCAndBoundedEntrySize(t *testing.T) {
	file, data := archiveFixture(t, fixtureEntry{"GO-2026-0001.json", `{"id":"GO-2026-0001"}`, 0})
	index := bytes.Index(data, []byte(`{"id"`))
	if index < 0 {
		t.Fatal("fixture not found")
	}
	data[index] = '['
	os.WriteFile(file, data, 0600)
	if err := readArchive(file, digest(data), &bytes.Buffer{}); err == nil {
		t.Fatal("CRC mismatch accepted")
	}
	file, data = archiveFixture(t, fixtureEntry{"GO-2026-0001.json", `{"id":"GO-2026-0001","details":"` + strings.Repeat("x", 2<<20) + `"}`, 0})
	if err := readArchive(file, digest(data), &bytes.Buffer{}); err == nil {
		t.Fatal("oversized entry accepted")
	}
}

func TestUbuntuProfileFiltersReleaseButValidatesWholeArchiveAndLargerOfficialRecords(t *testing.T) {
	selected := `{"id":"UBUNTU-SELECTED","affected":[{"package":{"ecosystem":"Ubuntu:24.04:LTS","name":"example"}}]}`
	foreign := `{"id":"UBUNTU-FOREIGN","affected":[{"package":{"ecosystem":"Ubuntu:22.04:LTS","name":"example"}}]}`
	large := `{"id":"USN-LARGE","affected":[{"package":{"ecosystem":"Ubuntu:24.04:LTS","name":"example"}}],"details":"` + strings.Repeat("a", 3<<20) + `"}`
	file, data := archiveFixture(t, fixtureEntry{"UBUNTU-SELECTED.json", selected, 0}, fixtureEntry{"UBUNTU-FOREIGN.json", foreign, 0}, fixtureEntry{"USN-LARGE.json", large, 0})
	if err := readArchive(file, digest(data), &bytes.Buffer{}); err == nil {
		t.Fatal("default profile silently widened its entry budget")
	}
	var output bytes.Buffer
	if err := readUbuntuArchive(file, digest(data), &output, "24.04"); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(output.String()), "\n")
	if len(lines) != 3 || strings.Contains(output.String(), `"id":"UBUNTU-FOREIGN"`) {
		t.Fatal("incorrect release filtering")
	}
	var marker struct{ Entries, EmittedEntries int }
	if json.Unmarshal([]byte(lines[2]), &marker) != nil || marker.Entries != 3 || marker.EmittedEntries != 2 {
		t.Fatal("lost whole-archive completion accounting")
	}
	// A filtered-out record still belongs to the frozen source and must pass CRC.
	index := bytes.Index(data, []byte(foreign))
	if index < 0 {
		t.Fatal("fixture missing")
	}
	data[index] = '['
	os.WriteFile(file, data, 0600)
	if err := readUbuntuArchive(file, digest(data), &bytes.Buffer{}, "24.04"); err == nil {
		t.Fatal("corruption of a filtered-out record accepted")
	}
	if err := readUbuntuArchive(file, digest(data), &bytes.Buffer{}, "other"); err == nil {
		t.Fatal("arbitrary Ubuntu profile accepted")
	}
}

func TestArchiveVersionReaderPreservesOriginalPrecisionWithoutTransportingDocuments(t *testing.T) {
	file, data := archiveFixture(t,
		fixtureEntry{"GO-1.json", `{"id":"GO-1","modified":"2026-10-31T00:00:00.123456789Z","details":"not part of the version stream"}`, 0},
		fixtureEntry{"GO-2.json", `{"id":"GO-2","modified":"2026-10-30T00:00:00Z"}`, 0})
	var output bytes.Buffer
	if err := readArchiveVersions(file, digest(data), &output, false); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(output.String()), "\n")
	var first struct{ Kind, ID, Modified string }
	if len(lines) != 3 || json.Unmarshal([]byte(lines[0]), &first) != nil || first.Kind != "version" || first.ID != "GO-1" || first.Modified != "2026-10-31T00:00:00.123456789Z" || strings.Contains(output.String(), "not part of") {
		t.Fatal("original timestamp lost or full document exposed", output.String())
	}
	if !strings.Contains(lines[2], `"kind":"complete"`) || !strings.Contains(lines[2], `"emittedEntries":2`) {
		t.Fatal("version stream lost full archive completion")
	}
}

func TestArchiveVersionReaderCannotCompleteMissingVersionsOrDamagedRecords(t *testing.T) {
	for _, document := range []string{`{"id":"GO-1"}`, `{"id":"GO-1","modified":null}`, `{"id":"GO-1","modified":123}`} {
		file, data := archiveFixture(t, fixtureEntry{"GO-1.json", document, 0})
		var output bytes.Buffer
		if err := readArchiveVersions(file, digest(data), &output, false); err == nil || strings.Contains(output.String(), `"kind":"complete"`) {
			t.Fatal("incomplete original version accepted")
		}
	}
	file, data := archiveFixture(t, fixtureEntry{"GO-1.json", `{"id":"GO-1","modified":"2026-10-31T00:00:00Z"}`, 0})
	if err := readArchiveVersions(file, strings.Repeat("f", 64), &bytes.Buffer{}, false); err == nil {
		t.Fatal("version reader bypassed archive digest")
	}
	index := bytes.Index(data, []byte(`{"id"`))
	data[index] = '['
	os.WriteFile(file, data, 0600)
	if err := readArchiveVersions(file, digest(data), &bytes.Buffer{}, false); err == nil {
		t.Fatal("version reader bypassed entry CRC")
	}
}

func TestUbuntuVersionReaderCoversAllOriginalScopes(t *testing.T) {
	file, data := archiveFixture(t,
		fixtureEntry{"UBUNTU-1.json", `{"id":"UBUNTU-1","modified":"2026-10-31T00:00:00Z","affected":[{"package":{"ecosystem":"Ubuntu:22.04:LTS"}}]}`, 0},
		fixtureEntry{"UBUNTU-2.json", `{"id":"UBUNTU-2","modified":"2026-10-30T00:00:00Z","affected":[{"package":{"ecosystem":"Ubuntu:24.04:Pro"}}]}`, 0})
	var output bytes.Buffer
	if err := readArchiveVersions(file, digest(data), &output, true); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), `"id":"UBUNTU-1"`) || !strings.Contains(output.String(), `"id":"UBUNTU-2"`) || strings.Contains(output.String(), "affected") {
		t.Fatal("full original version index was confused with scan eligibility")
	}
}

func TestVersionCLIUsesTheVerifiedOriginalArchiveProtocol(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "intelligence-unzip")
	if output, err := exec.Command("go", "build", "-o", binary, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %s %v", output, err)
	}
	file, data := archiveFixture(t, fixtureEntry{"GO-1.json", `{"id":"GO-1","modified":"2026-10-31T00:00:00.123456789Z"}`, 0})
	for _, flag := range []string{"--versions", "--versions-ubuntu"} {
		output, err := exec.Command(binary, file, digest(data), flag).CombinedOutput()
		if err != nil || !bytes.Contains(output, []byte(`"kind":"version"`)) || !bytes.Contains(output, []byte(`"modified":"2026-10-31T00:00:00.123456789Z"`)) || !bytes.Contains(output, []byte(`"kind":"complete"`)) {
			t.Fatalf("CLI %s: %s %v", flag, output, err)
		}
	}
}

func TestUbuntuProfileAllowsCurrentLargeOfficialRecordButKeepsUpperBound(t *testing.T) {
	for _, test := range []struct {
		size    int
		allowed bool
	}{{5 << 20, true}, {8 << 20, false}} {
		document := `{"id":"USN-OFFICIAL-LARGE","affected":[{"package":{"ecosystem":"Ubuntu:22.04:LTS","name":"example"}}],"details":"` + strings.Repeat("x", test.size) + `"}`
		file, data := archiveFixture(t, fixtureEntry{"USN-OFFICIAL-LARGE.json", document, 0})
		err := readUbuntuArchive(file, digest(data), &bytes.Buffer{}, "22.04")
		if (err == nil) != test.allowed {
			t.Fatalf("size=%d allowed=%v error=%v", test.size, test.allowed, err)
		}
	}
}
