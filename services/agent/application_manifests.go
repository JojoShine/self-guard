package main

import (
	"errors"
	"net/url"
	"sort"
	"strings"
)

// Locks prove resolved dependency versions, never that the software is installed.
func (r *applicationReader) npmLock(path string) error {
	b, err := r.bytesLimit(path, 8<<20)
	if err != nil {
		return err
	}
	var lock struct {
		LockfileVersion int `json:"lockfileVersion"`
		Name, Version   string
		Packages        map[string]struct {
			Name, Version string
			Link          bool
		}
	}
	if decodeApplicationJSON(b, &lock) != nil || (lock.LockfileVersion != 2 && lock.LockfileVersion != 3) || lock.Packages == nil {
		return errors.New("需要含packages的npm锁文件v2/v3，未将其他格式当作完整解析")
	}
	keys := make([]string, 0, len(lock.Packages))
	for key := range lock.Packages {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var incomplete error
	sha := applicationSHA(b)
	for _, key := range keys {
		p := lock.Packages[key]
		if p.Link {
			incomplete = errors.New("锁文件包含工作区或本地链接，需要读取实际部署元数据")
			continue
		}
		if key != "" && (!strings.HasPrefix(key, "node_modules/") || strings.Contains(key, "\\") || strings.Contains(key, "//") || strings.Contains("/"+key+"/", "/../")) {
			incomplete = errors.New("锁文件包含非注册表安装位置")
			continue
		}
		name := p.Name
		if name == "" {
			if key == "" {
				name = lock.Name
			} else {
				parts := strings.Split(key, "node_modules/")
				name = parts[len(parts)-1]
			}
		}
		if !installedSemver.MatchString(p.Version) {
			incomplete = errors.New("锁文件条目没有精确解析版本")
			continue
		}
		if err = r.appendRow(ApplicationComponent{Ecosystem: "npm", Name: name, Version: p.Version, Path: path + "!" + key, Provenance: "LOCK_FILE", SourceSHA256: sha}); err != nil {
			return err
		}
	}
	if len(keys) == 0 {
		return errors.New("锁文件没有组件")
	}
	return incomplete
}

type sbomComponent struct {
	Type                string `json:"type"`
	Ref                 string `json:"bom-ref"`
	Name, Version, Purl string
	Components          []sbomComponent
}

func purlIdentity(raw string) (string, string, string, error) {
	if !strings.HasPrefix(raw, "pkg:") || len(raw) > 4096 {
		return "", "", "", errors.New("SBOM组件缺少受支持的软件包标识")
	}
	value := strings.TrimPrefix(raw, "pkg:")
	value, _, _ = strings.Cut(value, "#")
	value, _, _ = strings.Cut(value, "?")
	kind, identity, ok := strings.Cut(value, "/")
	at := strings.LastIndex(identity, "@")
	if !ok || at <= 0 {
		return "", "", "", errors.New("SBOM软件包标识缺少精确版本")
	}
	name, err := url.PathUnescape(identity[:at])
	if err != nil {
		return "", "", "", err
	}
	version, err := url.PathUnescape(identity[at+1:])
	if err != nil || !applicationToken.MatchString(name) || !applicationToken.MatchString(version) {
		return "", "", "", errors.New("SBOM软件包标识无效")
	}
	parts := strings.Split(name, "/")
	switch kind {
	case "npm":
		if len(parts) > 2 || len(parts) == 2 && !strings.HasPrefix(parts[0], "@") {
			return "", "", "", errors.New("npm软件包命名空间无效")
		}
		return "npm", name, version, nil
	case "pypi":
		if len(parts) != 1 {
			return "", "", "", errors.New("Python软件包命名空间无效")
		}
		return "PyPI", name, version, nil
	case "maven":
		if len(parts) != 2 {
			return "", "", "", errors.New("Maven软件包坐标不完整")
		}
		return "Maven", parts[0] + ":" + parts[1], version, nil
	case "golang":
		return "Go", name, version, nil
	}
	return "", "", "", errors.New("SBOM该软件生态尚未覆盖")
}
func (r *applicationReader) sbom(path string) error {
	b, err := r.bytesLimit(path, 8<<20)
	if err != nil {
		return err
	}
	var bom struct {
		BomFormat, SpecVersion string
		Version                int
		Components             []sbomComponent
		Metadata               struct{ Component *sbomComponent }
		Dependencies           []struct {
			Ref       string
			DependsOn []string
		}
	}
	if decodeApplicationJSON(b, &bom) != nil || bom.BomFormat != "CycloneDX" || bom.SpecVersion != "1.6" || bom.Version < 1 {
		return errors.New("需要固定CycloneDX1.6 JSON及有效版本号")
	}
	items := []sbomComponent{}
	refs := map[string]bool{}
	var flatten func([]sbomComponent, int) error
	flatten = func(list []sbomComponent, depth int) error {
		if depth > 16 {
			return errors.New("SBOM组件嵌套超过16层")
		}
		for _, item := range list {
			if len(items) >= 10000 {
				return errors.New("SBOM组件超过10000项预算")
			}
			if item.Ref != "" {
				if len(item.Ref) > 1000 || refs[item.Ref] {
					return errors.New("SBOM组件引用重复或过长")
				}
				refs[item.Ref] = true
			}
			items = append(items, item)
			if err := flatten(item.Components, depth+1); err != nil {
				return err
			}
		}
		return nil
	}
	if bom.Metadata.Component != nil {
		if err = flatten([]sbomComponent{*bom.Metadata.Component}, 0); err != nil {
			return err
		}
	}
	if err = flatten(bom.Components, 0); err != nil {
		return err
	}
	if len(items) == 0 {
		return errors.New("SBOM没有可读取的软件组件")
	}
	edges := map[string][]string{}
	var incomplete error
	for _, relation := range bom.Dependencies {
		if !refs[relation.Ref] || len(relation.DependsOn) > 1000 {
			incomplete = errors.New("SBOM依赖引用缺失或超过预算")
			continue
		}
		if _, exists := edges[relation.Ref]; exists {
			return errors.New("SBOM依赖项重复定义")
		}
		edges[relation.Ref] = relation.DependsOn
		for _, ref := range relation.DependsOn {
			if !refs[ref] {
				incomplete = errors.New("SBOM依赖关系引用了不存在的组件")
			}
		}
	}
	sha := applicationSHA(b)
	for _, item := range items {
		ecosystem, name, version, e := purlIdentity(item.Purl)
		if e != nil {
			incomplete = e
			continue
		}
		if item.Version != "" && item.Version != version {
			incomplete = errors.New("SBOM版本字段与软件包标识存在冲突")
			continue
		}
		if item.Type != "library" && item.Type != "application" && item.Type != "framework" {
			incomplete = errors.New("SBOM包含当前尚未覆盖的组件类型")
			continue
		}
		if err = r.appendRow(ApplicationComponent{Ecosystem: ecosystem, Name: name, Version: version, Path: path, Provenance: "SBOM", SourceSHA256: sha, BomRef: item.Ref, DependsOn: edges[item.Ref]}); err != nil {
			return err
		}
	}
	return incomplete
}
