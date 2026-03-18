package filesystemanalyzer

import (
	"bufio"
	"bytes"
	"encoding/json"
	"go/parser"
	"go/token"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

type npmDependencyGraph struct {
	ManifestPath   string
	BaseDir        string
	Packages       []PackageRecord
	DependencyKeys map[string]map[string]struct{}
	ImportableKeys map[string]map[string]struct{}
}

type goDependencyGraph struct {
	ManifestPath   string
	BaseDir        string
	ModulePath     string
	Packages       []PackageRecord
	DirectKeys     map[string]struct{}
	ImportableKeys map[string]map[string]struct{}
}

func (g npmDependencyGraph) manifestBaseDir() string {
	return g.BaseDir
}

func (g goDependencyGraph) manifestBaseDir() string {
	return g.BaseDir
}

type npmLockPackage struct {
	Name         string            `json:"name"`
	Version      string            `json:"version"`
	Dependencies map[string]string `json:"dependencies"`
}

type npmLockDocument struct {
	Packages map[string]npmLockPackage `json:"packages"`
}

type npmLockV1Package struct {
	Version      string                      `json:"version"`
	Dependencies map[string]npmLockV1Package `json:"dependencies"`
}

type npmLockV1Document struct {
	Dependencies map[string]npmLockV1Package `json:"dependencies"`
}

var (
	jsRequirePattern    = regexp.MustCompile(`require\(\s*['"]([^'"]+)['"]\s*\)`)
	jsImportFromPattern = regexp.MustCompile(`from\s+['"]([^'"]+)['"]`)
	jsImportBarePattern = regexp.MustCompile(`import\s+['"]([^'"]+)['"]`)
	jsImportCallPattern = regexp.MustCompile(`import\(\s*['"]([^'"]+)['"]\s*\)`)
)

func parseNPMDependencyGraph(filePath string, data []byte) *npmDependencyGraph {
	var lock npmLockDocument
	if err := json.Unmarshal(data, &lock); err == nil && len(lock.Packages) > 0 {
		if graph := parseNPMDependencyGraphV2(filePath, lock); graph != nil {
			return graph
		}
	}

	var v1 npmLockV1Document
	if err := json.Unmarshal(data, &v1); err != nil || len(v1.Dependencies) == 0 {
		return nil
	}
	return parseNPMDependencyGraphV1(filePath, v1)
}

func parseNPMDependencyGraphV2(filePath string, lock npmLockDocument) *npmDependencyGraph {
	root, ok := lock.Packages[""]
	if !ok || len(root.Dependencies) == 0 {
		return nil
	}

	baseDir := path.Dir(filePath)
	if baseDir == "." {
		baseDir = ""
	}

	type queueItem struct {
		parentKey  string
		parentPath string
		name       string
		depth      int
	}

	packages := make(map[string]PackageRecord)
	dependencies := make(map[string]map[string]struct{})
	importableKeys := make(map[string]map[string]struct{})
	expandedPaths := make(map[string]struct{})
	queue := make([]queueItem, 0, len(root.Dependencies))
	for depName := range root.Dependencies {
		queue = append(queue, queueItem{name: depName, depth: 1})
	}

	for len(queue) > 0 {
		item := queue[0]
		queue = queue[1:]

		resolvedPath, dep, ok := resolveNPMLockPackage(lock.Packages, item.parentPath, item.name)
		if !ok {
			continue
		}
		record := PackageRecord{
			Ecosystem:        "npm",
			Manager:          "npm",
			Name:             firstNonEmpty(strings.TrimSpace(dep.Name), deriveNPMPackageName(resolvedPath)),
			Version:          strings.TrimSpace(dep.Version),
			Location:         filePath,
			DirectDependency: item.depth == 1,
			DependencyDepth:  item.depth,
		}
		if record.Name == "" || record.Version == "" {
			continue
		}
		record.PURL = buildPURL(record)
		key := packageInventoryKey(record)
		if existing, ok := packages[key]; ok {
			packages[key] = MergePackageRecord(existing, record)
		} else {
			packages[key] = record
		}
		if isRootImportableNPMPackagePath(resolvedPath, record.Name) {
			addImportablePackageKey(importableKeys, record.Name, key)
		}
		if item.parentKey != "" {
			if _, ok := dependencies[item.parentKey]; !ok {
				dependencies[item.parentKey] = make(map[string]struct{})
			}
			dependencies[item.parentKey][key] = struct{}{}
		}
		if _, seen := expandedPaths[resolvedPath]; seen {
			continue
		}
		expandedPaths[resolvedPath] = struct{}{}
		for childName := range dep.Dependencies {
			queue = append(queue, queueItem{
				parentKey:  key,
				parentPath: resolvedPath,
				name:       childName,
				depth:      item.depth + 1,
			})
		}
	}

	if len(packages) == 0 {
		return nil
	}
	out := make([]PackageRecord, 0, len(packages))
	for _, pkg := range packages {
		out = append(out, pkg)
	}
	sort.Slice(out, func(a, b int) bool {
		if out[a].DependencyDepth != out[b].DependencyDepth {
			return out[a].DependencyDepth < out[b].DependencyDepth
		}
		if out[a].Name != out[b].Name {
			return out[a].Name < out[b].Name
		}
		return out[a].Version < out[b].Version
	})
	return &npmDependencyGraph{
		ManifestPath:   filePath,
		BaseDir:        baseDir,
		Packages:       out,
		DependencyKeys: dependencies,
		ImportableKeys: importableKeys,
	}
}

func parseNPMDependencyGraphV1(filePath string, lock npmLockV1Document) *npmDependencyGraph {
	baseDir := path.Dir(filePath)
	if baseDir == "." {
		baseDir = ""
	}

	type queueItem struct {
		parentKey   string
		packagePath string
		name        string
		pkg         npmLockV1Package
		depth       int
	}

	packages := make(map[string]PackageRecord)
	dependencies := make(map[string]map[string]struct{})
	importableKeys := make(map[string]map[string]struct{})
	expandedPaths := make(map[string]struct{})
	queue := make([]queueItem, 0, len(lock.Dependencies))
	for depName, dep := range lock.Dependencies {
		queue = append(queue, queueItem{
			name:        depName,
			packagePath: path.Clean("node_modules/" + depName),
			pkg:         dep,
			depth:       1,
		})
	}

	for len(queue) > 0 {
		item := queue[0]
		queue = queue[1:]

		record := PackageRecord{
			Ecosystem:        "npm",
			Manager:          "npm",
			Name:             strings.TrimSpace(item.name),
			Version:          strings.TrimSpace(item.pkg.Version),
			Location:         filePath,
			DirectDependency: item.depth == 1,
			DependencyDepth:  item.depth,
		}
		if record.Name == "" || record.Version == "" {
			continue
		}
		record.PURL = buildPURL(record)
		key := packageInventoryKey(record)
		if existing, ok := packages[key]; ok {
			packages[key] = MergePackageRecord(existing, record)
		} else {
			packages[key] = record
		}
		if isRootImportableNPMPackagePath(item.packagePath, record.Name) {
			addImportablePackageKey(importableKeys, record.Name, key)
		}
		if item.parentKey != "" {
			if _, ok := dependencies[item.parentKey]; !ok {
				dependencies[item.parentKey] = make(map[string]struct{})
			}
			dependencies[item.parentKey][key] = struct{}{}
		}
		if _, seen := expandedPaths[item.packagePath]; seen {
			continue
		}
		expandedPaths[item.packagePath] = struct{}{}
		for childName, child := range item.pkg.Dependencies {
			queue = append(queue, queueItem{
				parentKey:   key,
				packagePath: path.Clean(item.packagePath + "/node_modules/" + childName),
				name:        childName,
				pkg:         child,
				depth:       item.depth + 1,
			})
		}
	}

	if len(packages) == 0 {
		return nil
	}
	out := make([]PackageRecord, 0, len(packages))
	for _, pkg := range packages {
		out = append(out, pkg)
	}
	sort.Slice(out, func(a, b int) bool {
		if out[a].DependencyDepth != out[b].DependencyDepth {
			return out[a].DependencyDepth < out[b].DependencyDepth
		}
		if out[a].Name != out[b].Name {
			return out[a].Name < out[b].Name
		}
		return out[a].Version < out[b].Version
	})
	return &npmDependencyGraph{
		ManifestPath:   filePath,
		BaseDir:        baseDir,
		Packages:       out,
		DependencyKeys: dependencies,
		ImportableKeys: importableKeys,
	}
}

func resolveNPMLockPackage(packages map[string]npmLockPackage, parentPath, depName string) (string, npmLockPackage, bool) {
	if depName == "" {
		return "", npmLockPackage{}, false
	}
	seen := make(map[string]struct{}, 4)
	currentPath := strings.TrimSpace(parentPath)
	for currentPath != "" {
		candidate := path.Clean(currentPath + "/node_modules/" + depName)
		if _, ok := seen[candidate]; !ok {
			seen[candidate] = struct{}{}
			if dep, ok := packages[candidate]; ok {
				return candidate, dep, true
			}
		}
		currentPath = npmParentPackagePath(currentPath)
	}
	rootCandidate := path.Clean("node_modules/" + depName)
	if dep, ok := packages[rootCandidate]; ok {
		return rootCandidate, dep, true
	}
	return "", npmLockPackage{}, false
}

func npmParentPackagePath(packagePath string) string {
	packagePath = strings.TrimSpace(packagePath)
	if packagePath == "" {
		return ""
	}
	parts := strings.Split(path.Clean(packagePath), "/")
	lastNodeModules := -1
	for idx, part := range parts {
		if part == "node_modules" {
			lastNodeModules = idx
		}
	}
	if lastNodeModules <= 0 {
		return ""
	}
	return strings.Join(parts[:lastNodeModules], "/")
}

func deriveNPMPackageName(packagePath string) string {
	packagePath = strings.TrimSpace(packagePath)
	if packagePath == "" {
		return ""
	}
	parts := strings.Split(packagePath, "/")
	lastNodeModules := -1
	for idx, part := range parts {
		if part == "node_modules" {
			lastNodeModules = idx
		}
	}
	if lastNodeModules >= 0 && lastNodeModules+1 < len(parts) {
		parts = parts[lastNodeModules+1:]
	}
	if len(parts) == 0 {
		return ""
	}
	if strings.HasPrefix(parts[0], "@") && len(parts) > 1 {
		return parts[0] + "/" + parts[1]
	}
	return parts[0]
}

func scanJSImportSpecifiers(data []byte) []string {
	if len(data) == 0 {
		return nil
	}
	text := string(data)
	matches := make([]string, 0)
	for _, pattern := range []*regexp.Regexp{jsRequirePattern, jsImportFromPattern, jsImportBarePattern, jsImportCallPattern} {
		for _, match := range pattern.FindAllStringSubmatch(text, -1) {
			if len(match) < 2 {
				continue
			}
			if pkg := normalizeJSImportPackage(match[1]); pkg != "" {
				matches = append(matches, pkg)
			}
		}
	}
	return dedupeStrings(matches)
}

func scanGoImportSpecifiers(filePath string, data []byte) []string {
	if len(data) == 0 {
		return nil
	}
	file, err := parser.ParseFile(token.NewFileSet(), filePath, data, parser.ImportsOnly)
	if err != nil || file == nil {
		return nil
	}
	imports := make([]string, 0, len(file.Imports))
	for _, imp := range file.Imports {
		if imp == nil {
			continue
		}
		value, err := strconv.Unquote(strings.TrimSpace(imp.Path.Value))
		if err != nil {
			continue
		}
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		imports = append(imports, value)
	}
	return dedupeStrings(imports)
}

func normalizeJSImportPackage(specifier string) string {
	specifier = strings.TrimSpace(specifier)
	if specifier == "" || strings.HasPrefix(specifier, ".") || strings.HasPrefix(specifier, "/") {
		return ""
	}
	parts := strings.Split(specifier, "/")
	if len(parts) == 0 {
		return ""
	}
	if strings.HasPrefix(parts[0], "@") {
		if len(parts) < 2 {
			return ""
		}
		return parts[0] + "/" + parts[1]
	}
	return parts[0]
}

func addImportablePackageKey(importableKeys map[string]map[string]struct{}, name, key string) {
	name = strings.TrimSpace(name)
	key = strings.TrimSpace(key)
	if name == "" || key == "" {
		return
	}
	if _, ok := importableKeys[name]; !ok {
		importableKeys[name] = make(map[string]struct{})
	}
	importableKeys[name][key] = struct{}{}
}

func isRootImportableNPMPackagePath(packagePath, packageName string) bool {
	packagePath = strings.TrimSpace(packagePath)
	packageName = strings.TrimSpace(packageName)
	if packagePath == "" || packageName == "" {
		return false
	}
	return path.Clean(packagePath) == path.Clean("node_modules/"+packageName)
}

func parseGoDependencyGraph(filePath string, data []byte) *goDependencyGraph {
	requirements := parseGoModRequirements(data)
	if len(requirements) == 0 {
		return nil
	}
	modulePath := parseGoModModulePath(data)

	baseDir := path.Dir(filePath)
	if baseDir == "." {
		baseDir = ""
	}

	packages := make(map[string]PackageRecord)
	directKeys := make(map[string]struct{})
	importableKeys := make(map[string]map[string]struct{})
	for _, req := range requirements {
		record := PackageRecord{
			Ecosystem:        "golang",
			Manager:          "go",
			Name:             strings.TrimSpace(req.Path),
			Version:          strings.TrimSpace(req.Version),
			Location:         filePath,
			DirectDependency: !req.Indirect,
		}
		switch {
		case req.Indirect:
			record.DependencyDepth = 2
		default:
			record.DependencyDepth = 1
		}
		if record.Name == "" || record.Version == "" {
			continue
		}
		record.PURL = buildPURL(record)
		key := packageInventoryKey(record)
		if existing, ok := packages[key]; ok {
			packages[key] = MergePackageRecord(existing, record)
		} else {
			packages[key] = record
		}
		if record.DirectDependency {
			directKeys[key] = struct{}{}
		}
		addImportablePackageKey(importableKeys, record.Name, key)
	}

	if len(packages) == 0 {
		return nil
	}
	out := make([]PackageRecord, 0, len(packages))
	for _, pkg := range packages {
		out = append(out, pkg)
	}
	sort.Slice(out, func(a, b int) bool {
		if out[a].DependencyDepth != out[b].DependencyDepth {
			return out[a].DependencyDepth < out[b].DependencyDepth
		}
		if out[a].Name != out[b].Name {
			return out[a].Name < out[b].Name
		}
		return out[a].Version < out[b].Version
	})
	return &goDependencyGraph{
		ManifestPath:   filePath,
		BaseDir:        baseDir,
		ModulePath:     modulePath,
		Packages:       out,
		DirectKeys:     directKeys,
		ImportableKeys: importableKeys,
	}
}

type goModRequirement struct {
	Path     string
	Version  string
	Indirect bool
}

func parseGoModRequirements(data []byte) []goModRequirement {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	requirements := make([]goModRequirement, 0)
	inRequireBlock := false
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "//") {
			continue
		}
		switch {
		case line == ")" && inRequireBlock:
			inRequireBlock = false
			continue
		case strings.HasPrefix(line, "require ("):
			inRequireBlock = true
			continue
		case strings.HasPrefix(line, "require "):
			requirement, ok := parseGoModRequirementLine(strings.TrimSpace(strings.TrimPrefix(line, "require ")))
			if ok {
				requirements = append(requirements, requirement)
			}
			continue
		case inRequireBlock:
			requirement, ok := parseGoModRequirementLine(line)
			if ok {
				requirements = append(requirements, requirement)
			}
		}
	}
	return requirements
}

func parseGoModModulePath(data []byte) string {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "//") {
			continue
		}
		if !strings.HasPrefix(line, "module ") {
			continue
		}
		line = strings.TrimSpace(strings.TrimPrefix(line, "module "))
		if idx := strings.Index(line, "//"); idx >= 0 {
			line = strings.TrimSpace(line[:idx])
		}
		return strings.Trim(strings.TrimSpace(line), `"`)
	}
	return ""
}

func parseGoModRequirementLine(line string) (goModRequirement, bool) {
	line = strings.TrimSpace(line)
	if line == "" {
		return goModRequirement{}, false
	}
	comment := ""
	if idx := strings.Index(line, "//"); idx >= 0 {
		comment = strings.TrimSpace(line[idx+2:])
		line = strings.TrimSpace(line[:idx])
	}
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return goModRequirement{}, false
	}
	return goModRequirement{
		Path:     strings.TrimSpace(fields[0]),
		Version:  strings.TrimSpace(fields[1]),
		Indirect: strings.Contains(comment, "indirect"),
	}, true
}

func matchGoImportablePackageKeys(importableKeys map[string]map[string]struct{}, importPath string) []string {
	importPath = strings.TrimSpace(importPath)
	if importPath == "" {
		return nil
	}
	longestPrefixLen := 0
	matches := make(map[string]struct{})
	for prefix, keys := range importableKeys {
		if prefix == "" {
			continue
		}
		if importPath != prefix && !strings.HasPrefix(importPath, prefix+"/") {
			continue
		}
		prefixLen := len(prefix)
		switch {
		case prefixLen > longestPrefixLen:
			clear(matches)
			longestPrefixLen = prefixLen
		case prefixLen < longestPrefixLen:
			continue
		}
		for key := range keys {
			matches[key] = struct{}{}
		}
	}
	if len(matches) == 0 {
		return nil
	}
	out := make([]string, 0, len(matches))
	for key := range matches {
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}
