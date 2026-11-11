package main

import (
	"archive/zip"
	"bufio"
	"bytes"
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path"
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
	root           *os.Root
	allowed        string
	deadline       time.Time
	metadataBytes  int64
	rows           []ApplicationComponent
	outputBytes    int
	archiveEntries int
	nestedArchives int
	archiveBytes   int64
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
func (r *applicationReader) jar(filePath string) error {
	f, size, sha, err := r.artifact(filePath)
	if err != nil {
		return err
	}
	defer f.Close()
	before, err := f.Stat()
	if err != nil {
		return errors.New("JAR制品状态不可读")
	}
	start, output := len(r.rows), r.outputBytes
	result := r.jarArchive(f, size, filePath, sha, 0)
	// Confirm the digest still describes the parsed file, including its pathname.
	hash := sha256.New()
	buffer := make([]byte, 64<<10)
	section := io.NewSectionReader(f, 0, size)
	for {
		if err = r.budget(); err != nil {
			break
		}
		n, readErr := section.Read(buffer)
		hash.Write(buffer[:n])
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			err = readErr
			break
		}
	}
	after, statErr := f.Stat()
	relative, _ := filepath.Rel(r.allowed, filePath)
	current, pathErr := r.root.Stat(relative)
	if err != nil || statErr != nil || pathErr != nil || !os.SameFile(before, current) || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) || hex.EncodeToString(hash.Sum(nil)) != sha || safePath(r.allowed, filePath) != nil {
		r.rows, r.outputBytes = r.rows[:start], output
		return errors.New("JAR制品在读取期间变化或校验超过预算")
	}
	return result
}

// Count central-directory records before archive/zip allocates an entry per record.
// ZIP64 and split archives are outside this bounded inventory profile.
func (r *applicationReader) jarDirectory(source io.ReaderAt, size int64) error {
	tailSize := int64(65557)
	if size < tailSize {
		tailSize = size
	}
	tail := make([]byte, int(tailSize))
	if _, err := source.ReadAt(tail, size-tailSize); err != nil {
		return errors.New("JAR目录不可读")
	}
	end := -1
	for i := len(tail) - 22; i >= 0; i-- {
		if binary.LittleEndian.Uint32(tail[i:]) == 0x06054b50 {
			// archive/zip selects the latest signature, even with trailing bytes.
			// Never skip it and validate a different, earlier directory instead.
			if i+22+int(binary.LittleEndian.Uint16(tail[i+20:])) != len(tail) {
				return errors.New("JAR结束标记含尾随数据、截断或歧义")
			}
			end = i
			break
		}
	}
	if end < 0 {
		return errors.New("JAR目录无效")
	}
	record := tail[end:]
	count := int(binary.LittleEndian.Uint16(record[10:]))
	directorySize := int64(binary.LittleEndian.Uint32(record[12:]))
	offset := int64(binary.LittleEndian.Uint32(record[16:]))
	if binary.LittleEndian.Uint32(record[4:]) != 0 || int(binary.LittleEndian.Uint16(record[8:])) != count || count == 65535 || offset == 0xffffffff || directorySize == 0xffffffff || r.archiveEntries+count > 10000 {
		return errors.New("JAR目录不受支持或累计超过10000项预算")
	}
	if directorySize > int64(32<<20)-r.metadataBytes {
		return errors.New("JAR目录元数据超过累计32MiB预算")
	}
	stop := size - tailSize + int64(end)
	cursor := stop - directorySize
	if cursor < offset || cursor < 0 {
		return errors.New("JAR目录偏移无效")
	}
	// archive/zip may fall back to the unadjusted offset for prefixed ZIPs.
	// Refuse two plausible directories so it cannot parse an unchecked one.
	if cursor > offset {
		signature := make([]byte, 4)
		if _, err := source.ReadAt(signature, offset); err != nil || binary.LittleEndian.Uint32(signature) == 0x02014b50 {
			return errors.New("JAR目录偏移存在歧义")
		}
	}
	header := make([]byte, 46)
	for n := 0; cursor < stop; n++ {
		if err := r.budget(); err != nil {
			return err
		}
		if n >= count || cursor+46 > stop {
			return errors.New("JAR目录数量冲突")
		}
		if _, err := source.ReadAt(header, cursor); err != nil || binary.LittleEndian.Uint32(header) != 0x02014b50 {
			return errors.New("JAR目录损坏")
		}
		cursor += 46 + int64(binary.LittleEndian.Uint16(header[28:])) + int64(binary.LittleEndian.Uint16(header[30:])) + int64(binary.LittleEndian.Uint16(header[32:]))
		if cursor > stop || cursor == stop && n+1 != count {
			return errors.New("JAR目录数量冲突")
		}
	}
	if cursor != stop || count > 0 && directorySize == 0 {
		return errors.New("JAR目录大小冲突")
	}
	r.archiveEntries += count
	r.metadataBytes += directorySize
	return nil
}

func (r *applicationReader) jarArchive(source io.ReaderAt, size int64, sourcePath, sha string, depth int) error {
	if err := r.budget(); err != nil {
		return err
	}
	if depth > 4 {
		return errors.New("JAR嵌套超过4层预算")
	}
	if err := r.jarDirectory(source, size); err != nil {
		return err
	}
	archive, err := zip.NewReader(source, size)
	if err != nil {
		return errors.New("JAR归档无效或损坏")
	}
	seen := map[string]bool{}
	for _, entry := range archive.File {
		if err := r.budget(); err != nil {
			return err
		}
		name := strings.TrimSuffix(entry.Name, "/")
		if name == "" || !utf8.ValidString(name) || path.Clean(name) != name || strings.HasPrefix(name, "/") || name == ".." || strings.HasPrefix(name, "../") || strings.ContainsAny(name, "\\!\x00\r\n") || seen[name] || entry.Mode()&os.ModeSymlink != 0 {
			return errors.New("JAR条目路径无效、重复或存在链接")
		}
		seen[name] = true
	}
	var incomplete error
	found := false
	coordinates := map[string]string{}
	coordinateRows := map[string][]int{}
	for _, entry := range archive.File {
		if err := r.budget(); err != nil {
			return err
		}
		lower := strings.ToLower(entry.Name)
		if strings.HasSuffix(lower, ".jar") || strings.HasSuffix(lower, ".war") || strings.HasSuffix(lower, ".zip") {
			r.nestedArchives++
			if r.nestedArchives > 100 {
				return errors.New("JAR嵌套制品超过100项预算")
			}
			if depth >= 4 {
				incomplete = errors.New("JAR嵌套超过4层预算")
				continue
			}
			b, e := r.jarEntry(entry, true)
			if e == nil {
				e = r.jarArchive(bytes.NewReader(b), int64(len(b)), sourcePath+"!"+entry.Name, applicationSHA(b), depth+1)
			}
			if e != nil {
				incomplete = e
			}
			continue
		}
		metadataPath := entry.Name
		for _, prefix := range []string{"BOOT-INF/classes/", "WEB-INF/classes/"} {
			metadataPath = strings.TrimPrefix(metadataPath, prefix)
		}
		if !strings.HasPrefix(metadataPath, "META-INF/maven/") || !strings.HasSuffix(metadataPath, "/pom.properties") {
			continue
		}
		found = true
		b, e := r.jarEntry(entry, false)
		if e != nil {
			incomplete = e
			continue
		}
		if !utf8.Valid(b) {
			incomplete = errors.New("JAR坐标不是有效UTF-8")
			continue
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
				if _, exists := fields[key]; exists {
					return errors.New("JAR坐标字段重复")
				}
				fields[key] = strings.TrimSpace(value)
			}
		}
		parts := strings.Split(metadataPath, "/")
		if len(parts) != 5 || parts[2] != fields["groupId"] || parts[3] != fields["artifactId"] || !applicationToken.MatchString(fields["groupId"]) || !applicationToken.MatchString(fields["artifactId"]) || strings.ContainsAny(fields["groupId"]+fields["artifactId"], ":/\\") || fields["version"] == "" {
			return errors.New("JAR缺少完整Maven坐标")
		}
		identity := fields["groupId"] + ":" + fields["artifactId"]
		if previous, exists := coordinates[identity]; exists && previous != fields["version"] {
			// Incomplete collection does not invalidate a reported installed row.
			// Retract this archive's ambiguous identity, preserving nested evidence.
			positions := coordinateRows[identity]
			dropped := 0
			kept := r.rows[:0]
			for index, row := range r.rows {
				if dropped < len(positions) && index == positions[dropped] {
					encoded, _ := json.Marshal(row)
					r.outputBytes -= len(encoded)
					dropped++
					continue
				}
				kept = append(kept, row)
			}
			r.rows = kept
			return errors.New("JAR同一Maven坐标包含冲突版本")
		}
		coordinates[identity] = fields["version"]
		if e = r.append("Maven", identity, fields["version"], sourcePath+"!"+entry.Name, sha); e != nil {
			return e
		}
		coordinateRows[identity] = append(coordinateRows[identity], len(r.rows)-1)
	}
	if !found {
		incomplete = errors.New("JAR没有Maven坐标，无法仅凭文件名确认软件版本")
	}
	return incomplete
}

func (r *applicationReader) jarEntry(entry *zip.File, nested bool) ([]byte, error) {
	if err := r.budget(); err != nil {
		return nil, err
	}
	limit, remaining := int64(65536), int64(32<<20)-r.metadataBytes
	if nested {
		limit, remaining = 16<<20, int64(256<<20)-r.archiveBytes
	}
	if remaining < limit {
		limit = remaining
	}
	if limit < 0 || entry.UncompressedSize64 > uint64(limit) {
		return nil, errors.New("JAR解码超过坐标64KiB/累计32MiB或嵌套制品16MiB/累计256MiB预算")
	}
	reader, err := entry.Open()
	if err != nil {
		return nil, errors.New("JAR条目不可读")
	}
	defer reader.Close()
	// Exact allocation avoids bytes.Buffer growth retaining twice the bytes at
	// each recursive level; at most four 16MiB nested buffers remain live.
	b := make([]byte, int(entry.UncompressedSize64))
	for offset := 0; offset < len(b); {
		if err := r.budget(); err != nil {
			return nil, err
		}
		end := offset + (32 << 10)
		if end > len(b) {
			end = len(b)
		}
		n, readErr := io.ReadFull(reader, b[offset:end])
		if nested {
			r.archiveBytes += int64(n)
		} else {
			r.metadataBytes += int64(n)
		}
		offset += n
		if readErr != nil {
			return nil, errors.New("JAR条目读取、大小或CRC校验失败")
		}
	}
	if err := r.budget(); err != nil {
		return nil, err
	}
	var extra [1]byte
	if n, err := reader.Read(extra[:]); n != 0 || err != io.EOF {
		return nil, errors.New("JAR条目大小或CRC校验失败")
	}
	return b, nil
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
