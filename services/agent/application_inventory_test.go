package main

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func applicationFile(t *testing.T, root, relative, contents string) string {
	t.Helper()
	file := filepath.Join(root, relative)
	if err := os.MkdirAll(filepath.Dir(file), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte(contents), 0600); err != nil {
		t.Fatal(err)
	}
	return file
}
func TestActualApplicationMetadataIsReadWithoutExecutingPackageCommands(t *testing.T) {
	root := t.TempDir()
	app := filepath.Join(root, "app")
	applicationFile(t, root, "app/package.json", `{"name":"web-app","version":"1.0.0","scripts":{"postinstall":"must never execute"}}`)
	applicationFile(t, root, "app/node_modules/@scope/parser/package.json", `{"name":"@scope/parser","version":"2.3.4"}`)
	applicationFile(t, root, "python/Requests-2.0.dist-info/METADATA", "Metadata-Version: 2.1\nName: Requests\nVersion: 2.0\nRequires-Dist: urllib3 (>=1)\n\nPrivate description must not be reported\n")
	components, status := applicationInventory(root, []ApplicationInput{{Format: "NPM_INSTALLED_TREE", Path: app}, {Format: "PYTHON_SITE_PACKAGES", Path: filepath.Join(root, "python")}})
	if !status.Complete || len(components) != 3 {
		t.Fatalf("%+v %+v", components, status)
	}
	for _, c := range components {
		if c.Version == "" || c.SourceSHA256 == "" || c.Provenance != "INSTALLED_METADATA" || !strings.HasPrefix(c.Path, root+"/") {
			t.Fatalf("missing actual provenance: %+v", c)
		}
	}
}
func TestApplicationInventoryRefusesEscapesLinksRangesAndMissingMetadata(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	applicationFile(t, outside, "package.json", `{"name":"outside","version":"1.0.0"}`)
	if err := os.Symlink(outside, filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	for _, input := range []ApplicationInput{{Format: "NPM_INSTALLED_TREE", Path: outside}, {Format: "NPM_INSTALLED_TREE", Path: filepath.Join(root, "link")}, {Format: "SHELL", Path: root}, {Format: "PYTHON_SITE_PACKAGES", Path: filepath.Join(root, "missing")}} {
		c, s := applicationInventory(root, []ApplicationInput{input})
		if s.Complete || len(c) > 0 {
			t.Fatalf("invalid input accepted %+v %+v", c, s)
		}
	}
	applicationFile(t, root, "bad/package.json", `{"name":"declared","version":"^1.2.3"}`)
	c, s := applicationInventory(root, []ApplicationInput{{Format: "NPM_INSTALLED_TREE", Path: filepath.Join(root, "bad")}})
	if s.Complete || len(c) != 0 {
		t.Fatal("declared range treated as installed version")
	}
	applicationFile(t, root, "python/bad.dist-info/METADATA", "Name: sample\nVersion: 1.0\nVersion: 9.9\n")
	_, s = applicationInventory(root, []ApplicationInput{{Format: "PYTHON_SITE_PACKAGES", Path: filepath.Join(root, "python")}})
	if s.Complete {
		t.Fatal("duplicate version treated as reliable")
	}
}
func TestJarMetadataHasCoordinatesAndNestedArchivesRemainVisibleAsIncomplete(t *testing.T) {
	root := t.TempDir()
	var b bytes.Buffer
	z := zip.NewWriter(&b)
	w, _ := z.Create("META-INF/maven/org.apache.logging.log4j/log4j-core/pom.properties")
	w.Write([]byte("groupId=org.apache.logging.log4j\nartifactId=log4j-core\nversion=2.14.1\n"))
	w, _ = z.Create("BOOT-INF/lib/embedded.jar")
	w.Write([]byte("not executed"))
	z.Close()
	file := applicationFile(t, root, "app.jar", b.String())
	c, s := applicationInventory(root, []ApplicationInput{{Format: "MAVEN_JAR", Path: file}})
	if len(c) != 1 || c[0].Name != "org.apache.logging.log4j:log4j-core" || c[0].Version != "2.14.1" || s.Complete {
		t.Fatalf("%+v %+v", c, s)
	}
}
func TestApplicationInventoryBudgetsDoNotPretendFullCoverage(t *testing.T) {
	root := t.TempDir()
	applicationFile(t, root, "app/package.json", `{"name":"app","version":"1.0.0","description":"`+strings.Repeat("x", (1<<20)+1)+`"}`)
	_, s := applicationInventory(root, []ApplicationInput{{Format: "NPM_INSTALLED_TREE", Path: filepath.Join(root, "app")}})
	if s.Complete {
		t.Fatal("oversized metadata treated as complete")
	}
}

func TestApplicationMetadataRejectsDuplicateCaseVersionsAndInvalidUTF8(t *testing.T) {
	root := t.TempDir()
	for _, contents := range []string{`{"name":"sample","version":"1.0.0","Version":"9.9.9"}`, "{\"name\":\"bad\xff\",\"version\":\"1.0.0\"}"} {
		applicationFile(t, root, "app/package.json", contents)
		_, s := applicationInventory(root, []ApplicationInput{{Format: "NPM_INSTALLED_TREE", Path: filepath.Join(root, "app")}})
		if s.Complete {
			t.Fatal("ambiguous or invalid metadata accepted")
		}
	}
}
func TestActualGoBinaryReportsItsBuildVersionWithoutRunningIt(t *testing.T) {
	root := t.TempDir()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(executable)
	if err != nil {
		t.Fatal(err)
	}
	file := applicationFile(t, root, "agent-test-binary", string(data))
	rows, _ := applicationInventory(root, []ApplicationInput{{Format: "GO_BINARY", Path: file}})
	if len(rows) == 0 || rows[0].Name != "stdlib" || !installedSemver.MatchString(rows[0].Version) {
		t.Fatalf("missing actual Go build version: %+v", rows)
	}
}

func TestApplicationProfilePathsAndKindsAreExplicit(t *testing.T) {
	good := []ApplicationInput{{Format: "GO_BINARY", Path: "/srv/apps/service"}}
	if validateApplicationInputs("/srv/apps", good) != nil {
		t.Fatal("valid read scope refused")
	}
	for _, inputs := range [][]ApplicationInput{{{Format: "SHELL", Path: "/srv/apps/run"}}, {{Format: "GO_BINARY", Path: "/etc/shadow"}}, append(good, good...)} {
		if validateApplicationInputs("/srv/apps", inputs) == nil {
			t.Fatal("invalid read scope accepted")
		}
	}
	profile := installationProfile{CollectionRoot: "/srv/apps", ApplicationInputs: good}
	config, err := applyInstallationProfile(Config{}, profile)
	if err != nil || len(config.ApplicationInputs) != 1 {
		t.Fatalf("profile lost application inputs: %+v %v", config, err)
	}
}
func TestResolvedLocksAndSBOMAreExplicitlyReportedRatherThanClaimedInstalled(t *testing.T) {
	root := t.TempDir()
	lock := applicationFile(t, root, "package-lock.json", `{"lockfileVersion":3,"packages":{"node_modules/@scope/sample":{"version":"1.2.3"},"node_modules/transitive":{"version":"2.0.0"}}}`)
	sbom := applicationFile(t, root, "bom.json", `{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":[{"type":"library","bom-ref":"log4j","name":"log4j-core","version":"2.14.1","purl":"pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"},{"type":"library","bom-ref":"go","name":"stdlib","version":"1.18.0","purl":"pkg:golang/stdlib@1.18.0"}],"dependencies":[{"ref":"go","dependsOn":["log4j"]}]}`)
	rows, status := applicationInventory(root, []ApplicationInput{{Format: "NPM_LOCK_FILE", Path: lock}, {Format: "CYCLONEDX_1_6", Path: sbom}})
	if !status.Complete || len(rows) != 4 {
		t.Fatalf("%+v %+v", rows, status)
	}
	if rows[0].Provenance != "LOCK_FILE" || rows[2].Provenance != "SBOM" || rows[3].BomRef != "go" || len(rows[3].DependsOn) != 1 {
		t.Fatalf("provenance or dependency identity lost: %+v", rows)
	}
}
func TestSBOMDoesNotSilentlyAcceptConflictingIdentityOrMissingDependencyReferences(t *testing.T) {
	root := t.TempDir()
	for _, body := range []string{`{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":[{"type":"library","bom-ref":"a","name":"sample","version":"2.0.0","purl":"pkg:npm/sample@1.0.0"}]}`, `{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":[{"type":"library","bom-ref":"a","name":"sample","version":"1.0.0","purl":"pkg:npm/sample@1.0.0"}],"dependencies":[{"ref":"a","dependsOn":["missing"]}]}`} {
		file := applicationFile(t, root, "bom.json", body)
		_, status := applicationInventory(root, []ApplicationInput{{Format: "CYCLONEDX_1_6", Path: file}})
		if status.Complete {
			t.Fatal("ambiguous SBOM treated as complete")
		}
	}
}
