package main

import (
	"archive/zip"
	"bufio"
	"bytes"
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"
)

type ApplicationInput struct {
	Format string `json:"format"`
	Path   string `json:"path"`
}
type ApplicationComponent struct {
	Ecosystem    string   `json:"ecosystem"`
	Name         string   `json:"name"`
	Version      string   `json:"version"`
	Path         string   `json:"path"`
	Provenance   string   `json:"provenance"`
	SourceSHA256 string   `json:"sourceSha256"`
	BomRef       string   `json:"bomRef,omitempty"`
	DependsOn    []string `json:"dependsOn,omitempty"`
}
type ApplicationInputStatus struct {
	Format   string `json:"format"`
	Path     string `json:"path"`
	Complete bool   `json:"complete"`
	Reason   string `json:"reason"`
}
type ApplicationCollection struct {
	Complete bool                     `json:"complete"`
	Reason   string                   `json:"reason"`
	Inputs   []ApplicationInputStatus `json:"inputs"`
}
type applicationReader struct {
	root          *os.Root
	allowed       string
	deadline      time.Time
	metadataBytes int64
	rows          []ApplicationComponent
	outputBytes   int
}

var installedSemver = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$`)
var applicationToken = regexp.MustCompile(`^[^\x00-\x20\x7f]{1,500}$`)

func applicationInventory(allowed string, inputs []ApplicationInput) ([]ApplicationComponent, ApplicationCollection) {
	status := ApplicationCollection{Complete: true, Reason: "已完成明确授权的应用清单读取", Inputs: []ApplicationInputStatus{}}
	rows := []ApplicationComponent{}
	if len(inputs) == 0 {
		return rows, status
	}
	fail := func(reason string) { status.Complete = false; status.Reason = reason }
	if allowed == "" || allowed == "/" || !filepath.IsAbs(allowed) || safePath(allowed, allowed) != nil {
		fail("应用采集目录未授权或存在链接")
		return rows, status
	}
	before, err := os.Lstat(allowed)
	if err != nil {
		fail("应用采集目录不可读")
		return rows, status
	}
	root, err := os.OpenRoot(allowed)
	if err != nil {
		fail("应用采集目录不可读")
		return rows, status
	}
	defer root.Close()
	opened, err := root.Stat(".")
	if err != nil || !os.SameFile(before, opened) {
		fail("应用采集目录读取期间变化")
		return rows, status
	}
	reader := applicationReader{root: root, allowed: allowed, deadline: time.Now().Add(10 * time.Second), rows: rows}
	if len(inputs) > 100 {
		inputs = inputs[:100]
		fail("应用采集输入超过100项限制")
	}
	for _, input := range inputs {
		var reason error
		switch input.Format {
		case "NPM_INSTALLED_TREE":
			reason = reader.npm(input.Path, 0)
		case "PYTHON_SITE_PACKAGES":
			reason = reader.python(input.Path)
		case "MAVEN_JAR":
			reason = reader.jar(input.Path)
		case "NPM_LOCK_FILE":
			reason = reader.npmLock(input.Path)
		case "CYCLONEDX_1_6":
			reason = reader.sbom(input.Path)
		case "GO_BINARY":
			reason = reader.goBinary(input.Path)
		default:
			reason = errors.New("未支持的应用清单格式")
		}
		item := ApplicationInputStatus{Format: input.Format, Path: input.Path, Complete: reason == nil, Reason: "已读取实际部署元数据"}
		if reason != nil {
			item.Reason = reason.Error()
			fail("部分应用清单无法完整读取，请查看各输入说明")
		}
		status.Inputs = append(status.Inputs, item)
	}
	return reader.rows, status
}
func (r *applicationReader) budget() error {
	if time.Now().After(r.deadline) {
		return errors.New("应用采集超过10秒时间预算")
	}
	return nil
}
func (r *applicationReader) open(path string, directory bool) (*os.File, error) {
	if err := r.budget(); err != nil {
		return nil, err
	}
	relative, err := filepath.Rel(r.allowed, path)
	if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(os.PathSeparator)) || safePath(r.allowed, path) != nil {
		return nil, errors.New("输入不在授权目录内、不可读或存在链接")
	}
	f, err := r.root.OpenFile(relative, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, errors.New("应用元数据不可读")
	}
	info, err := f.Stat()
	if err != nil || directory && !info.IsDir() || !directory && !info.Mode().IsRegular() {
		f.Close()
		return nil, errors.New("输入类型不符，不能读取特殊文件")
	}
	return f, nil
}
func (r *applicationReader) bytes(path string) ([]byte, error) { return r.bytesLimit(path, 1<<20) }
func (r *applicationReader) bytesLimit(path string, limit int64) ([]byte, error) {
	f, err := r.open(path, false)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	before, _ := f.Stat()
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	after, statErr := f.Stat()
	if statErr != nil || before == nil || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		return nil, errors.New("应用元数据在读取期间变化")
	}
	r.metadataBytes += int64(len(b))
	if err != nil || int64(len(b)) > limit || r.metadataBytes > 32<<20 {
		return nil, errors.New("应用元数据超过单文件或累计32MiB预算")
	}
	return b, nil
}
func (r *applicationReader) directories(path string) ([]os.DirEntry, error) {
	f, err := r.open(path, true)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	items, err := f.ReadDir(5001)
	if err != nil && err != io.EOF {
		return nil, errors.New("无法完整读取目录")
	}
	if len(items) > 5000 {
		return nil, errors.New("应用目录超过5000项预算")
	}
	return items, nil
}
func (r *applicationReader) append(ecosystem, name, version, path, sha string) error {
	if !applicationToken.MatchString(name) || !applicationToken.MatchString(version) {
		return errors.New("软件名称或版本缺失、过长或含控制字符")
	}
	return r.appendRow(ApplicationComponent{Ecosystem: ecosystem, Name: name, Version: version, Path: path, Provenance: "INSTALLED_METADATA", SourceSHA256: sha})
}
func (r *applicationReader) appendRow(row ApplicationComponent) error {
	if !applicationToken.MatchString(row.Name) || !applicationToken.MatchString(row.Version) {
		return errors.New("软件标识缺失或无效")
	}
	b, _ := json.Marshal(row)
	if len(r.rows) >= 2000 || r.outputBytes+len(b) > 256<<10 {
		return errors.New("应用清单超过2000组件或256KiB上报预算")
	}
	r.outputBytes += len(b)
	r.rows = append(r.rows, row)
	return nil
}
func applicationSHA(b []byte) string { sum := sha256.Sum256(b); return hex.EncodeToString(sum[:]) }
func (r *applicationReader) npm(path string, depth int) error {
	if depth > 16 {
		return errors.New("嵌套安装目录超过16层预算")
	}
	b, err := r.bytes(filepath.Join(path, "package.json"))
	if err != nil {
		return err
	}
	var p struct {
		Name, Version string
		Dependencies  map[string]string `json:"dependencies"`
	}
	if decodeApplicationJSON(b, &p) != nil || !installedSemver.MatchString(p.Version) {
		return errors.New("npm元数据缺少精确安装版本，声明范围不能作实际版本")
	}
	if err = r.append("npm", p.Name, p.Version, filepath.Join(path, "package.json"), applicationSHA(b)); err != nil {
		return err
	}
	modules := filepath.Join(path, "node_modules")
	relative, _ := filepath.Rel(r.allowed, modules)
	if _, err = r.root.Lstat(relative); os.IsNotExist(err) {
		if len(p.Dependencies) > 0 && depth == 0 {
			return errors.New("应用声明了依赖但没有已安装node_modules，不能以声明版本代替")
		}
		return nil
	}
	entries, err := r.directories(modules)
	if err != nil {
		return err
	}
	var incomplete error
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".") {
			continue
		}
		if !entry.IsDir() && entry.Type()&os.ModeSymlink == 0 {
			continue
		}
		child := filepath.Join(modules, entry.Name())
		if strings.HasPrefix(entry.Name(), "@") {
			scoped, e := r.directories(child)
			if e != nil {
				incomplete = e
				continue
			}
			for _, item := range scoped {
				if e = r.npm(filepath.Join(child, item.Name()), depth+1); e != nil {
					incomplete = e
				}
			}
		} else if e := r.npm(child, depth+1); e != nil {
			incomplete = e
		}
		if err = r.budget(); err != nil {
			return err
		}
	}
	return incomplete
}
func (r *applicationReader) python(path string) error {
	entries, err := r.directories(path)
	if err != nil {
		return err
	}
	var incomplete error
	found := false
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".dist-info") {
			continue
		}
		found = true
		file := filepath.Join(path, entry.Name(), "METADATA")
		b, e := r.bytes(file)
		if e != nil {
			incomplete = e
			continue
		}
		if !utf8.Valid(b) {
			incomplete = errors.New("Python元数据不是有效UTF-8")
			continue
		}
		fields := map[string]string{}
		scan := bufio.NewScanner(strings.NewReader(string(b)))
		for scan.Scan() {
			line := strings.TrimSuffix(scan.Text(), "\r")
			if line == "" {
				break
			}
			key, value, ok := strings.Cut(line, ":")
			if !ok {
				continue
			}
			if key == "Name" || key == "Version" {
				if fields[key] != "" {
					e = errors.New("Python元数据包含重复名称或版本")
					break
				}
				fields[key] = strings.TrimSpace(value)
			}
		}
		if scan.Err() != nil {
			e = errors.New("Python元数据头超过读取预算")
		}
		if e == nil {
			e = r.append("PyPI", fields["Name"], fields["Version"], file, applicationSHA(b))
		}
		if e != nil {
			incomplete = e
		}
	}
	if !found {
		return errors.New("没有找到已安装分发的dist-info元数据")
	}
	return incomplete
}
func (r *applicationReader) artifact(path string) (*os.File, int64, string, error) {
	f, err := r.open(path, false)
	if err != nil {
		return nil, 0, "", err
	}
	info, err := f.Stat()
	if err != nil || info.Size() > 128<<20 {
		f.Close()
		return nil, 0, "", errors.New("应用制品超过128MiB读取预算")
	}
	hash := sha256.New()
	buffer := make([]byte, 64<<10)
	for {
		if err = r.budget(); err != nil {
			f.Close()
			return nil, 0, "", err
		}
		n, e := f.Read(buffer)
		hash.Write(buffer[:n])
		if e == io.EOF {
			break
		}
		if e != nil {
			f.Close()
			return nil, 0, "", errors.New("无法完整读取应用制品")
		}
	}
	after, err := f.Stat()
	if err != nil || after.Size() != info.Size() || !after.ModTime().Equal(info.ModTime()) {
		f.Close()
		return nil, 0, "", errors.New("应用制品在读取期间变化")
	}
	return f, info.Size(), hex.EncodeToString(hash.Sum(nil)), nil
}
func (r *applicationReader) jar(path string) error {
	f, size, sha, err := r.artifact(path)
	if err != nil {
		return err
	}
	defer f.Close()
	archive, err := zip.NewReader(f, size)
	if err != nil || len(archive.File) > 10000 {
		return errors.New("JAR归档无效或超过10000项预算")
	}
	var incomplete error
	found := false
	for _, entry := range archive.File {
		if strings.HasSuffix(entry.Name, ".jar") {
			incomplete = errors.New("JAR含嵌套制品，当前输入尚未覆盖其内部组件")
		}
		if !strings.HasPrefix(entry.Name, "META-INF/maven/") || !strings.HasSuffix(entry.Name, "/pom.properties") {
			continue
		}
		found = true
		if entry.UncompressedSize64 > 65536 {
			return errors.New("JAR软件坐标超过64KiB预算")
		}
		reader, e := entry.Open()
		if e != nil {
			return errors.New("JAR坐标不可读")
		}
		b, e := io.ReadAll(io.LimitReader(reader, 65537))
		closeErr := reader.Close()
		r.metadataBytes += int64(len(b))
		if e != nil || closeErr != nil || len(b) > 65536 || r.metadataBytes > 32<<20 {
			return errors.New("JAR坐标读取、CRC或预算校验失败")
		}
		fields := map[string]string{}
		for _, line := range strings.Split(string(b), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!") {
				continue
			}
			key, value, ok := strings.Cut(line, "=")
			key = strings.TrimSpace(key)
			if !ok || strings.ContainsAny(value, "\\\r") {
				return errors.New("JAR坐标采用尚未完整解释的属性转义")
			}
			if key == "groupId" || key == "artifactId" || key == "version" {
				if fields[key] != "" {
					return errors.New("JAR坐标字段重复")
				}
				fields[key] = strings.TrimSpace(value)
			}
		}
		if fields["groupId"] == "" || fields["artifactId"] == "" || fields["version"] == "" {
			return errors.New("JAR缺少完整Maven坐标")
		}
		if e = r.append("Maven", fields["groupId"]+":"+fields["artifactId"], fields["version"], path+"!"+entry.Name, sha); e != nil {
			return e
		}
	}
	if !found {
		return errors.New("JAR没有Maven坐标，无法仅凭文件名确认软件版本")
	}
	return incomplete
}
func (r *applicationReader) goBinary(path string) error {
	f, _, sha, err := r.artifact(path)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := buildinfo.Read(f)
	if err != nil {
		return errors.New("制品没有可读取的Go构建信息")
	}
	version := strings.TrimPrefix(info.GoVersion, "go")
	if !installedSemver.MatchString(version) {
		return errors.New("Go运行时版本不是可核对的正式版本")
	}
	if err = r.append("Go", "stdlib", version, path, sha); err != nil {
		return err
	}
	var incomplete error
	for _, m := range append(info.Deps, &info.Main) {
		if m.Path == "" {
			continue
		}
		if m.Replace != nil {
			m = m.Replace
		}
		if m.Version == "" || m.Version == "(devel)" {
			incomplete = errors.New("Go模块没有可核对版本，可能是本地替换或开发构建")
			continue
		}
		if err = r.append("Go", m.Path, m.Version, path, sha); err != nil {
			return err
		}
	}
	return incomplete
}

func decodeApplicationJSON(b []byte, target any) error {
	if !utf8.Valid(b) {
		return errors.New("应用元数据不是有效UTF-8")
	}
	decoder := json.NewDecoder(bytes.NewReader(b))
	decoder.UseNumber()
	var visit func(int) error
	visit = func(depth int) error {
		if depth > 64 {
			return errors.New("应用元数据嵌套超过预算")
		}
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delimiter, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		if delimiter != '{' && delimiter != '[' {
			return errors.New("应用元数据JSON无效")
		}
		seen := map[string]bool{}
		for decoder.More() {
			if delimiter == '{' {
				key, err := decoder.Token()
				if err != nil {
					return err
				}
				name, ok := key.(string)
				fold := strings.ToLower(name)
				if !ok || seen[fold] {
					return errors.New("应用元数据字段重复")
				}
				seen[fold] = true
			}
			if err := visit(depth + 1); err != nil {
				return err
			}
		}
		_, err = decoder.Token()
		return err
	}
	if err := visit(0); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return errors.New("应用元数据包含多余内容")
	}
	return json.Unmarshal(b, target)
}

func validateApplicationInputs(root string, inputs []ApplicationInput) error {
	if len(inputs) > 100 {
		return errors.New("应用采集输入超过100项限制")
	}
	seen := map[string]bool{}
	for _, input := range inputs {
		if !validCollectionPath(root) || !validCollectionPath(input.Path) || !strings.HasPrefix(input.Path, root+"/") {
			return errors.New("应用采集输入需要明确授权的非根目录")
		}
		switch input.Format {
		case "NPM_INSTALLED_TREE", "PYTHON_SITE_PACKAGES", "MAVEN_JAR", "GO_BINARY", "NPM_LOCK_FILE", "CYCLONEDX_1_6":
		default:
			return errors.New("应用采集格式未支持")
		}
		key := input.Format + "\x00" + input.Path
		if seen[key] {
			return errors.New("应用采集输入重复")
		}
		seen[key] = true
	}
	return nil
}
