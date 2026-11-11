package main

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type mavenTestEntry struct {
	name string
	data []byte
}

func mavenTestZIP(t *testing.T, entries ...mavenTestEntry) []byte {
	t.Helper()
	var b bytes.Buffer
	z := zip.NewWriter(&b)
	for _, entry := range entries {
		w, err := z.Create(entry.name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = w.Write(entry.data); err != nil {
			t.Fatal(err)
		}
	}
	if err := z.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}
func mavenTestCoordinate(group, artifact, version string) mavenTestEntry {
	return mavenTestEntry{"META-INF/maven/" + group + "/" + artifact + "/pom.properties", []byte("groupId=" + group + "\nartifactId=" + artifact + "\nversion=" + version + "\n")}
}
func TestNestedMavenSpringBootAndWARHaveActualProvenance(t *testing.T) {
	for _, location := range []string{"BOOT-INF/lib/spring-boot.jar", "WEB-INF/lib/spring-boot.jar", "WEB-INF/lib-provided/spring-boot.jar"} {
		t.Run(location, func(t *testing.T) {
			root := t.TempDir()
			nested := mavenTestZIP(t, mavenTestCoordinate("org.springframework.boot", "spring-boot", "2.6.0"))
			outer := mavenTestZIP(t, mavenTestCoordinate("example", "app", "1.0"), mavenTestEntry{location, nested})
			file := applicationFile(t, root, "app.war", string(outer))
			rows, status := applicationInventory(root, []ApplicationInput{{Format: "MAVEN_JAR", Path: file}})
			if !status.Complete || len(rows) != 2 {
				t.Fatalf("rows=%+v status=%+v", rows, status)
			}
			row := rows[1]
			if row.Name != "org.springframework.boot:spring-boot" || row.Version != "2.6.0" || row.Path != file+"!"+location+"!META-INF/maven/org.springframework.boot/spring-boot/pom.properties" || row.SourceSHA256 != applicationSHA(nested) || row.Provenance != "INSTALLED_METADATA" {
				t.Fatalf("lost nested identity: %+v", row)
			}
		})
	}
}
func TestNestedMavenRecursesAndKeepsUnknownCoverageIncomplete(t *testing.T) {
	root := t.TempDir()
	leaf := mavenTestZIP(t, mavenTestCoordinate("example", "leaf", "2.0"))
	middle := mavenTestZIP(t, mavenTestCoordinate("example", "middle", "1.0"), mavenTestEntry{"lib/leaf.jar", leaf})
	outer := mavenTestZIP(t, mavenTestCoordinate("example", "app", "1.0"), mavenTestEntry{"BOOT-INF/lib/middle.jar", middle})
	file := applicationFile(t, root, "app.jar", string(outer))
	rows, status := applicationInventory(root, []ApplicationInput{{Format: "MAVEN_JAR", Path: file}})
	if !status.Complete || len(rows) != 3 || rows[2].SourceSHA256 != applicationSHA(leaf) {
		t.Fatalf("%+v %+v", rows, status)
	}
	for _, nested := range [][]byte{[]byte("corrupt"), mavenTestZIP(t, mavenTestEntry{"org/example.class", []byte("class")})} {
		file = applicationFile(t, root, "bad.jar", string(mavenTestZIP(t, mavenTestCoordinate("example", "app", "1.0"), mavenTestEntry{"BOOT-INF/lib/unknown.jar", nested})))
		rows, status = applicationInventory(root, []ApplicationInput{{Format: "MAVEN_JAR", Path: file}})
		if status.Complete || len(rows) != 1 || status.Inputs[0].Reason == "" {
			t.Fatalf("unknown silently complete: %+v %+v", rows, status)
		}
	}
}
func TestMavenRejectsCoordinateIdentityConflictsAndAmbiguousPaths(t *testing.T) {
	good := mavenTestCoordinate("example", "app", "1.0")
	cases := [][]mavenTestEntry{
		{{"META-INF/maven/other/app/pom.properties", good.data}},
		{good, good},
		{good, {"BOOT-INF/classes/META-INF/maven/example/app/pom.properties", mavenTestCoordinate("example", "app", "2.0").data}},
		{{"META-INF/maven/example/app/pom.properties", []byte("groupId=example\nartifactId=app\nversion=1.0\nversion=2.0\n")}},
		{{"../META-INF/maven/example/app/pom.properties", good.data}},
		{good, {"../BOOT-INF/lib/escape.jar", mavenTestZIP(t, good)}},
		{good, {"BOOT-INF/lib/link.jar", []byte("not a zip")}},
	}
	for i, entries := range cases {
		root := t.TempDir()
		file := applicationFile(t, root, "app.jar", string(mavenTestZIP(t, entries...)))
		_, status := applicationInventory(root, []ApplicationInput{{Format: "MAVEN_JAR", Path: file}})
		if status.Complete {
			t.Fatalf("case %d accepted ambiguity", i)
		}
	}
}
func TestNestedMavenBoundsDepthAndDecodeBudgets(t *testing.T) {
	nested := mavenTestZIP(t, mavenTestCoordinate("example", "leaf", "1.0"))
	for i := 0; i < 6; i++ {
		nested = mavenTestZIP(t, mavenTestCoordinate("example", "app", "1.0"), mavenTestEntry{"lib/nested.jar", nested})
	}
	root := t.TempDir()
	file := applicationFile(t, root, "app.jar", string(nested))
	_, status := applicationInventory(root, []ApplicationInput{{Format: "MAVEN_JAR", Path: file}})
	if status.Complete {
		t.Fatal("deep nested archive accepted")
	}
	f, err := os.OpenRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	for _, r := range []*applicationReader{
		{root: f, allowed: root, deadline: time.Now().Add(time.Second), metadataBytes: 32 << 20},
		{root: f, allowed: root, deadline: time.Now().Add(-time.Second)},
		{root: f, allowed: root, deadline: time.Now().Add(time.Second), archiveBytes: 256 << 20},
	} {
		if err := r.jar(file); err == nil {
			t.Fatal("exhausted budget accepted")
		}
	}
	bomb := mavenTestZIP(t, mavenTestCoordinate("example", "app", "1.0"), mavenTestEntry{"lib/bomb.jar", []byte(strings.Repeat("0", (32<<20)+1))})
	file = applicationFile(t, root, filepath.Base("bomb.jar"), string(bomb))
	_, status = applicationInventory(root, []ApplicationInput{{Format: "MAVEN_JAR", Path: file}})
	if status.Complete {
		t.Fatal("oversized nested decode accepted")
	}
}

func TestNestedMavenRejectsCRCAndEntryCountCorruption(t *testing.T) {
	leaf := mavenTestZIP(t, mavenTestCoordinate("example", "leaf", "1.0"))
	outer := mavenTestZIP(t, mavenTestCoordinate("example", "app", "1.0"), mavenTestEntry{"BOOT-INF/lib/leaf.jar", leaf})
	z, err := zip.NewReader(bytes.NewReader(outer), int64(len(outer)))
	if err != nil {
		t.Fatal(err)
	}
	offset, err := z.File[1].DataOffset()
	if err != nil {
		t.Fatal(err)
	}
	outer[offset] ^= 0xff
	root := t.TempDir()
	file := applicationFile(t, root, "corrupt.jar", string(outer))
	rows, status := applicationInventory(root, []ApplicationInput{{Format: "MAVEN_JAR", Path: file}})
	if status.Complete || len(rows) != 1 {
		t.Fatalf("corrupt nested bytes trusted: %+v %+v", rows, status)
	}
	// Dishonest EOCD counts must fail before archive/zip allocates all entries.
	many := mavenTestZIP(t, mavenTestCoordinate("example", "app", "1.0"), mavenTestEntry{"file", []byte("data")})
	end := len(many) - 22
	many[end+8] = 1
	many[end+10] = 1
	file = applicationFile(t, root, "count.jar", string(many))
	_, status = applicationInventory(root, []ApplicationInput{{Format: "MAVEN_JAR", Path: file}})
	if status.Complete {
		t.Fatal("conflicting directory count accepted")
	}
}

func TestNestedMavenCapsAggregateEntryAndArtifactCounts(t *testing.T) {
	root := t.TempDir()
	leaf := mavenTestZIP(t, mavenTestCoordinate("example", "leaf", "1.0"))
	entries := []mavenTestEntry{mavenTestCoordinate("example", "app", "1.0")}
	for i := 0; i < 101; i++ {
		entries = append(entries, mavenTestEntry{fmt.Sprintf("lib/%d.jar", i), leaf})
	}
	file := applicationFile(t, root, "many.jar", string(mavenTestZIP(t, entries...)))
	_, status := applicationInventory(root, []ApplicationInput{{Format: "MAVEN_JAR", Path: file}})
	if status.Complete || !strings.Contains(status.Inputs[0].Reason, "100") {
		t.Fatalf("nested count silently complete: %+v", status)
	}
	entries = entries[:1]
	for i := 0; i < 10000; i++ {
		entries = append(entries, mavenTestEntry{fmt.Sprintf("classes/%d", i), nil})
	}
	file = applicationFile(t, root, "entries.jar", string(mavenTestZIP(t, entries...)))
	_, status = applicationInventory(root, []ApplicationInput{{Format: "MAVEN_JAR", Path: file}})
	if status.Complete || !strings.Contains(status.Inputs[0].Reason, "10000") {
		t.Fatalf("entry count silently complete: %+v", status)
	}
}

func TestMavenSupportsExecutablePrefixAndClassMetadata(t *testing.T) {
	for _, prefix := range []string{"", "BOOT-INF/classes/", "WEB-INF/classes/"} {
		coordinate := mavenTestCoordinate("example", "app", "1.0")
		coordinate.name = prefix + coordinate.name
		archive := append([]byte("#!/bin/sh\n# never run\n"), mavenTestZIP(t, coordinate)...)
		root := t.TempDir()
		file := applicationFile(t, root, "boot.jar", string(archive))
		rows, status := applicationInventory(root, []ApplicationInput{{Format: "MAVEN_JAR", Path: file}})
		if !status.Complete || len(rows) != 1 || rows[0].SourceSHA256 != applicationSHA(archive) {
			t.Fatalf("prefix %q: %+v %+v", prefix, rows, status)
		}
	}
}

func TestNestedMavenReadsDeploymentsLargerThanMetadataBudget(t *testing.T) {
	// A stored, deterministic high-entropy resource models an ordinary sizeable
	// dependency without relying on an extreme ZIP compression ratio.
	resource := make([]byte, 8<<20)
	if _, err := rand.New(rand.NewSource(11)).Read(resource); err != nil {
		t.Fatal(err)
	}
	var leaf bytes.Buffer
	z := zip.NewWriter(&leaf)
	coordinate := mavenTestCoordinate("example", "large-dependency", "1.0")
	for _, entry := range []mavenTestEntry{coordinate, {"resource.bin", resource}} {
		w, err := z.CreateHeader(&zip.FileHeader{Name: entry.name, Method: zip.Store})
		if err != nil {
			t.Fatal(err)
		}
		if _, err = w.Write(entry.data); err != nil {
			t.Fatal(err)
		}
	}
	if err := z.Close(); err != nil {
		t.Fatal(err)
	}
	entries := []mavenTestEntry{mavenTestCoordinate("example", "app", "1.0")}
	for i := 0; i < 5; i++ {
		entries = append(entries, mavenTestEntry{fmt.Sprintf("BOOT-INF/lib/dependency-%d.jar", i), leaf.Bytes()})
	}
	root := t.TempDir()
	file := filepath.Join(root, "large-app.jar")
	f, err := os.Create(file)
	if err != nil {
		t.Fatal(err)
	}
	// Spring Boot stores nested JAR entries. Stream the outer archive to disk
	// so this regression exercises collection without buffering another 40MiB.
	outer := zip.NewWriter(f)
	for _, entry := range entries {
		w, err := outer.CreateHeader(&zip.FileHeader{Name: entry.name, Method: zip.Store})
		if err != nil {
			t.Fatal(err)
		}
		if _, err = w.Write(entry.data); err != nil {
			t.Fatal(err)
		}
	}
	if err = outer.Close(); err != nil {
		t.Fatal(err)
	}
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
	rows, status := applicationInventory(root, []ApplicationInput{{Format: "MAVEN_JAR", Path: file}})
	if !status.Complete || len(rows) != 6 {
		t.Fatalf("ordinary >32MiB deployment rejected: rows=%d status=%+v", len(rows), status)
	}
}

// Optional acceptance bridge: emit actual collector output from known deployed
// fixture bytes for matching against the API's real official advisory catalog.
func TestExportApplicationInventoryFixture(t *testing.T) {
	output := os.Getenv("SELF_GUARD_APPLICATION_FIXTURE_OUTPUT")
	if output == "" {
		t.Skip("set SELF_GUARD_APPLICATION_FIXTURE_OUTPUT to export collected fixture evidence")
	}
	if !filepath.IsAbs(output) {
		t.Fatal("fixture output must be an absolute path")
	}
	root := t.TempDir()
	dependency := mavenTestZIP(t, mavenTestCoordinate("org.springframework.boot", "spring-boot", "2.6.0"))
	jar := applicationFile(t, root, "spring-boot-app.jar", string(mavenTestZIP(t, mavenTestCoordinate("example", "app", "1.0"), mavenTestEntry{"BOOT-INF/lib/spring-boot-2.6.0.jar", dependency})))
	applicationFile(t, root, "node-app/package.json", `{"name":"lodash","version":"4.17.20"}`)
	rows, status := applicationInventory(root, []ApplicationInput{{Format: "MAVEN_JAR", Path: jar}, {Format: "NPM_INSTALLED_TREE", Path: filepath.Join(root, "node-app")}})
	if !status.Complete || len(rows) != 3 {
		t.Fatalf("fixture collection incomplete: %+v %+v", rows, status)
	}
	body, err := json.MarshalIndent(struct {
		Components []ApplicationComponent `json:"components"`
		Collection ApplicationCollection  `json:"collection"`
	}{rows, status}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(output, append(body, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
}

func TestMavenConflictDiscardsOnlyConflictingArchiveIdentity(t *testing.T) {
	root := t.TempDir()
	dependency := mavenTestZIP(t, mavenTestCoordinate("example", "app", "9.0"))
	outer := mavenTestZIP(t,
		mavenTestCoordinate("example", "app", "1.0"),
		mavenTestEntry{"BOOT-INF/lib/independent.jar", dependency},
		mavenTestEntry{"BOOT-INF/classes/META-INF/maven/example/app/pom.properties", mavenTestCoordinate("example", "app", "1.0").data},
		mavenTestEntry{"WEB-INF/classes/META-INF/maven/example/app/pom.properties", mavenTestCoordinate("example", "app", "2.0").data},
	)
	file := applicationFile(t, root, "conflict.jar", string(outer))
	rows, status := applicationInventory(root, []ApplicationInput{{Format: "MAVEN_JAR", Path: file}})
	if status.Complete || len(status.Inputs) != 1 || !strings.Contains(status.Inputs[0].Reason, "冲突") {
		t.Fatalf("conflict hidden: %+v", status)
	}
	if len(rows) != 1 || rows[0].Version != "9.0" || rows[0].SourceSHA256 != applicationSHA(dependency) || !strings.Contains(rows[0].Path, "!BOOT-INF/lib/independent.jar!") {
		t.Fatalf("conflicting installed identity retained or independent component lost: %+v", rows)
	}
	// Removed rows must release exactly their serialized output budget.
	handle, err := os.OpenRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	defer handle.Close()
	reader := applicationReader{root: handle, allowed: root, deadline: time.Now().Add(10 * time.Second)}
	if reader.jar(file) == nil {
		t.Fatal("conflicting archive reported complete")
	}
	encoded, err := json.Marshal(rows[0])
	if err != nil {
		t.Fatal(err)
	}
	if reader.outputBytes != len(encoded) {
		t.Fatalf("output budget includes discarded rows: got %d want %d", reader.outputBytes, len(encoded))
	}
}

func TestMavenDirectoryRejectsAmbiguousEOCDBeforeZipAllocation(t *testing.T) {
	entries := []mavenTestEntry{mavenTestCoordinate("example", "app", "1.0")}
	for i := 0; i < 10000; i++ {
		entries = append(entries, mavenTestEntry{fmt.Sprintf("entry-%d", i), nil})
	}
	real := mavenTestZIP(t, entries...)
	originalEnd := append([]byte(nil), real[len(real)-22:]...)
	wrapper := make([]byte, 22)
	binary.LittleEndian.PutUint32(wrapper, 0x06054b50)
	binary.LittleEndian.PutUint32(wrapper[16:], uint32(len(real)))
	binary.LittleEndian.PutUint16(wrapper[20:], 23)
	data := append(append(append(append([]byte(nil), real...), wrapper...), originalEnd...), byte('X'))
	// Go's selector accepts the copied, later EOCD despite its trailing byte.
	// Our preflight must reject it, rather than validating the empty wrapper.
	archive, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil || len(archive.File) != 10001 {
		t.Fatalf("invalid ambiguity regression fixture: %v", err)
	}
	reader := applicationReader{deadline: time.Now().Add(10 * time.Second)}
	if err = reader.jarDirectory(bytes.NewReader(data), int64(len(data))); err == nil {
		t.Fatalf("preflight validated another directory: entries=%d metadata=%d", reader.archiveEntries, reader.metadataBytes)
	}
}
