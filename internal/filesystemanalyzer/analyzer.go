package filesystemanalyzer

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"debug/pe"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"net"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/writer/cerebro/internal/scanner"
)

const (
	defaultMaxWalkEntries        = 100000
	defaultMaxFileBytes    int64 = 4 << 20
	defaultMaxSecretBytes  int64 = 1 << 20
	defaultMaxMalwareBytes int64 = 2 << 20
)

var (
	awsAccessKeyPattern            = regexp.MustCompile(`AKIA[0-9A-Z]{16}`)
	jwtTokenPattern                = regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b`)
	githubTokenPattern             = regexp.MustCompile(`gh[pousr]_[A-Za-z0-9_]{20,}`)
	gitlabTokenPattern             = regexp.MustCompile(`glpat-[A-Za-z0-9_-]{20,}`)
	npmTokenPattern                = regexp.MustCompile(`npm_[A-Za-z0-9]{36}`)
	slackTokenPattern              = regexp.MustCompile(`xox(?:[abprs]-|e[a-z]-)[A-Za-z0-9-]{10,}`)
	gcpAPIKeyPattern               = regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`)
	googleOAuthClientSecretPattern = regexp.MustCompile(`GOCSPX-[0-9A-Za-z\-_]{20,}`)
	stripeAPIKeyPattern            = regexp.MustCompile(`\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b`)
	twilioAPIKeyPattern            = regexp.MustCompile(`\bSK[0-9a-f]{32}\b`)
	sendGridAPIKeyPattern          = regexp.MustCompile(`\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b`)
	mailgunKeyPattern              = regexp.MustCompile(`\bkey-[0-9a-fA-F]{32}\b`)
	privateKeyPattern              = regexp.MustCompile(`-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP |ENCRYPTED )?PRIVATE KEY-----`)
	inlineSecretPattern            = regexp.MustCompile(`(?i)(password|passwd|pwd|secret|token|api[_-]?key|client[_-]?secret|connection[_-]?string|access[_-]?key|private[_-]?key)\s*[:=]`)
	inlineSecretAssignmentPattern  = regexp.MustCompile(`(?i)(password|passwd|pwd|secret|token|api[_-]?key|client[_-]?secret|connection[_-]?string|access[_-]?key|private[_-]?key)\s*[:=]\s*(.+)$`)
	secretTokenPattern             = regexp.MustCompile(`[A-Za-z0-9+/=_-]{20,}`)
	databaseURLPattern             = regexp.MustCompile(`(?i)(?:jdbc:sqlserver://[^\s'"]+|(?:jdbc:)?(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|sqlserver)://[^\s'"]+)`)
)

type Analyzer struct {
	vulnerabilityScanner scanner.FilesystemScanner
	vulnerabilityMatcher PackageVulnerabilityMatcher
	secretScanner        SecretScanner
	malwareScanner       MalwareScanner
	now                  func() time.Time
	maxWalkEntries       int
	maxFileBytes         int64
	maxSecretFileBytes   int64
	maxMalwareFileBytes  int64
}

func New(opts Options) *Analyzer {
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	maxWalk := opts.MaxWalkEntries
	if maxWalk <= 0 {
		maxWalk = defaultMaxWalkEntries
	}
	maxFileBytes := opts.MaxFileBytes
	if maxFileBytes <= 0 {
		maxFileBytes = defaultMaxFileBytes
	}
	maxSecretBytes := opts.MaxSecretFileBytes
	if maxSecretBytes <= 0 {
		maxSecretBytes = defaultMaxSecretBytes
	}
	maxMalwareBytes := opts.MaxMalwareFileBytes
	if maxMalwareBytes <= 0 {
		maxMalwareBytes = defaultMaxMalwareBytes
	}
	return &Analyzer{
		vulnerabilityScanner: opts.VulnerabilityScanner,
		vulnerabilityMatcher: opts.VulnerabilityMatcher,
		secretScanner:        opts.SecretScanner,
		malwareScanner:       opts.MalwareScanner,
		now:                  now,
		maxWalkEntries:       maxWalk,
		maxFileBytes:         maxFileBytes,
		maxSecretFileBytes:   maxSecretBytes,
		maxMalwareFileBytes:  maxMalwareBytes,
	}
}

func (a *Analyzer) Analyze(ctx context.Context, rootfsPath string) (*Report, error) {
	if a == nil {
		a = New(Options{})
	}
	rootfsPath = strings.TrimSpace(rootfsPath)
	if rootfsPath == "" {
		return nil, fmt.Errorf("filesystem path is required")
	}
	absPath, err := filepath.Abs(rootfsPath)
	if err != nil {
		return nil, fmt.Errorf("resolve filesystem path %s: %w", rootfsPath, err)
	}
	report := &Report{
		Analyzer:    "filesystem",
		GeneratedAt: a.now().UTC(),
		Metadata: map[string]any{
			"rootfs_path": absPath,
		},
	}
	if a.vulnerabilityScanner != nil {
		vulnResult, err := a.vulnerabilityScanner.ScanFilesystem(ctx, absPath)
		if err != nil {
			report.Metadata["vulnerability_scan_error"] = err.Error()
		} else if vulnResult != nil {
			report.Vulnerabilities = append(report.Vulnerabilities, vulnResult.Vulnerabilities...)
			report.Findings = append(report.Findings, vulnResult.Findings...)
			report.OS.Name = firstNonEmpty(report.OS.Name, vulnResult.OS)
			report.OS.Architecture = firstNonEmpty(report.OS.Architecture, vulnResult.Architecture)
		}
	}
	if a.secretScanner != nil {
		secretResult, err := a.secretScanner.ScanFilesystem(ctx, absPath)
		if err != nil {
			report.Metadata["secret_scan_error"] = err.Error()
		} else if secretResult != nil {
			if strings.TrimSpace(secretResult.Engine) != "" {
				report.Metadata["secret_scan_engine"] = strings.TrimSpace(secretResult.Engine)
			}
			invSecrets := secretResult.Findings
			for idx := range invSecrets {
				invSecrets[idx] = normalizeSecretFinding(invSecrets[idx])
			}
			if len(invSecrets) > 0 {
				report.Secrets = append(report.Secrets, invSecrets...)
			}
		}
	}
	root, err := os.OpenRoot(absPath)
	if err != nil {
		return nil, fmt.Errorf("open filesystem root %s: %w", absPath, err)
	}
	defer func() { _ = root.Close() }()

	inv := newInventory(report.GeneratedAt)
	if len(report.Secrets) > 0 {
		inv.addSecrets(report.Secrets...)
		report.Secrets = nil
	}
	walkErr := fs.WalkDir(root.FS(), ".", func(filePath string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			inv.metadataErrors = append(inv.metadataErrors, walkErr.Error())
			return nil
		}
		if filePath == "." {
			return nil
		}
		inv.entriesVisited++
		if inv.entriesVisited > a.maxWalkEntries {
			inv.truncated = true
			return fs.SkipAll
		}
		name := d.Name()
		if d.IsDir() {
			if shouldSkipDir(filePath, name) {
				return fs.SkipDir
			}
			info, err := d.Info()
			if err == nil && isWorldWritableDir(info.Mode(), filePath) {
				inv.addConfig(ConfigFinding{
					ID:          findingID("world_writable_dir", filePath),
					Type:        "filesystem_permissions",
					Severity:    "medium",
					Path:        filePath,
					Title:       "World-writable directory",
					Description: "Directory is writable by all users.",
					Remediation: "Restrict directory permissions to the minimum required scope.",
				})
			}
			return nil
		}
		info, err := d.Info()
		if err != nil {
			inv.metadataErrors = append(inv.metadataErrors, err.Error())
			return nil
		}
		if info.Mode()&os.ModeSetuid != 0 {
			inv.addConfig(ConfigFinding{
				ID:          findingID("suid_binary", filePath),
				Type:        "filesystem_permissions",
				Severity:    "high",
				Path:        filePath,
				Title:       "SUID binary present",
				Description: "Binary carries the setuid bit and can execute with elevated privileges.",
				Remediation: "Remove the setuid bit unless the binary is explicitly required and reviewed.",
			})
		}
		if filePath == "var/run/docker.sock" || filePath == "run/docker.sock" {
			inv.addConfig(ConfigFinding{
				ID:          findingID("docker_socket", filePath),
				Type:        "container_runtime",
				Severity:    "high",
				Path:        filePath,
				Title:       "Docker socket exposed",
				Description: "Docker daemon socket is present inside the filesystem.",
				Remediation: "Avoid mounting the Docker socket into workloads and restrict daemon access.",
			})
		}
		if shouldParsePackageFile(filePath) {
			if data, ok, err := readLimitedFile(root, filePath, a.maxFileBytes); err == nil && ok {
				if graph := parseNPMDependencyGraph(filePath, data); graph != nil {
					inv.addNPMDependencyGraph(*graph)
				} else if graph := parseGoDependencyGraph(filePath, data); graph != nil {
					inv.addGoDependencyGraph(*graph)
				} else {
					inv.addPackages(parsePackageRecords(filePath, data)...)
				}
			} else if err != nil {
				inv.metadataErrors = append(inv.metadataErrors, err.Error())
			}
		}
		if shouldInspectJSImportFile(filePath, info.Mode(), info.Size(), a.maxFileBytes) {
			if data, ok, err := readLimitedFile(root, filePath, a.maxFileBytes); err == nil && ok {
				inv.addJSImportFile(filePath, scanJSImportSpecifiers(data))
			} else if err != nil {
				inv.metadataErrors = append(inv.metadataErrors, err.Error())
			}
		}
		if shouldInspectGoImportFile(filePath, info.Mode(), info.Size(), a.maxFileBytes) {
			if data, ok, err := readLimitedFile(root, filePath, a.maxFileBytes); err == nil && ok {
				inv.addGoImportFile(filePath, scanGoImportSpecifiers(filePath, data))
			} else if err != nil {
				inv.metadataErrors = append(inv.metadataErrors, err.Error())
			}
		}
		if shouldParseOSFile(filePath) {
			if data, ok, err := readLimitedFile(root, filePath, a.maxFileBytes); err == nil && ok {
				mergeOSInfo(&inv.os, parseOSInfo(filePath, data))
			} else if err != nil {
				inv.metadataErrors = append(inv.metadataErrors, err.Error())
			}
		}
		if shouldInspectPEBinary(filePath, info.Mode(), info.Size(), a.maxFileBytes) {
			if data, ok, err := readLimitedFile(root, filePath, a.maxFileBytes); err == nil && ok {
				pkg, findings, osInfo, inspectErr := inspectPEBinary(filePath, data)
				if inspectErr != nil {
					inv.metadataErrors = append(inv.metadataErrors, inspectErr.Error())
				}
				if pkg != nil {
					inv.addPackages(*pkg)
				}
				if len(findings) > 0 {
					inv.addConfigs(findings...)
				}
				mergeOSInfo(&inv.os, osInfo)
			} else if err != nil {
				inv.metadataErrors = append(inv.metadataErrors, err.Error())
			}
		}
		if shouldParseConfigFile(filePath) {
			if data, ok, err := readLimitedFile(root, filePath, a.maxSecretFileBytes); err == nil && ok {
				inv.addConfigs(parseConfigFindings(filePath, data)...)
			} else if err != nil {
				inv.metadataErrors = append(inv.metadataErrors, err.Error())
			}
		}
		if shouldInspectTechnologyFile(filePath, info.Mode(), info.Size(), a.maxFileBytes) {
			if data, ok, err := readLimitedFile(root, filePath, a.maxFileBytes); err == nil && ok {
				inv.addTechnologies(detectTechnologies(filePath, data)...)
			} else if err != nil {
				inv.metadataErrors = append(inv.metadataErrors, err.Error())
			}
		}
		if shouldInspectIaCFile(filePath, info.Mode(), info.Size(), a.maxSecretFileBytes) {
			if data, ok, err := readLimitedFile(root, filePath, a.maxSecretFileBytes); err == nil && ok {
				artifacts, findings := inspectIaCFile(filePath, data)
				inv.addIaCArtifacts(artifacts...)
				inv.addConfigs(findings...)
			} else if err != nil {
				inv.metadataErrors = append(inv.metadataErrors, err.Error())
			}
		}
		if shouldSecretScan(filePath, info.Mode(), info.Size(), a.maxSecretFileBytes) {
			if data, ok, err := readLimitedFile(root, filePath, a.maxSecretFileBytes); err == nil && ok {
				inv.addSecrets(scanSecrets(filePath, data)...)
			} else if err != nil {
				inv.metadataErrors = append(inv.metadataErrors, err.Error())
			}
		}
		if a.malwareScanner != nil && shouldMalwareScan(filePath, info.Mode(), info.Size(), a.maxMalwareFileBytes) {
			if data, ok, err := readLimitedFile(root, filePath, a.maxMalwareFileBytes); err == nil && ok {
				result, scanErr := a.malwareScanner.ScanData(ctx, data, filePath)
				if scanErr != nil {
					inv.metadataErrors = append(inv.metadataErrors, scanErr.Error())
				} else if result != nil && result.Malicious {
					inv.addMalware(MalwareFinding{
						ID:          findingID("malware", filePath),
						Path:        filePath,
						Hash:        result.Hash,
						MalwareType: result.MalwareType,
						MalwareName: result.MalwareName,
						Severity:    "critical",
						Confidence:  result.Confidence,
						Engine:      result.Engine,
					})
				}
			} else if err != nil {
				inv.metadataErrors = append(inv.metadataErrors, err.Error())
			}
		}
		return nil
	})
	if walkErr != nil && !errors.Is(walkErr, fs.SkipAll) {
		return nil, fmt.Errorf("walk filesystem %s: %w", absPath, walkErr)
	}

	mergeOSInfo(&report.OS, inv.os)
	report.OS.EOL = isLikelyEOL(report.OS)
	inv.applyDependencyReachability()
	inv.canonicalizeGraphBackedPackages()
	report.Packages = inv.sortedPackages()
	if a.vulnerabilityMatcher != nil && len(report.Packages) > 0 {
		matchedVulns, err := a.vulnerabilityMatcher.MatchPackages(ctx, report.OS, report.Packages)
		if err != nil {
			report.Metadata["vulnerability_match_error"] = err.Error()
		} else {
			report.Vulnerabilities = dedupeVulnerabilities(append(report.Vulnerabilities, matchedVulns...))
			report.Findings = append(report.Findings, buildVulnerabilityFindings(matchedVulns)...)
		}
	}
	report.Secrets = inv.secrets
	report.Misconfigurations = inv.configs
	report.IaCArtifacts = inv.iacArtifacts
	report.Malware = inv.malware
	report.Technologies = inv.sortedTechnologies()
	report.SBOM = buildSBOM(report.GeneratedAt, inv.sortedSBOMComponents(report.Packages), inv.sortedSBOMDependencies())
	report.Findings = dedupeFindings(append(report.Findings, inv.findings...))
	report.Summary = Summary{
		PackageCount:          len(report.Packages),
		DependencyCount:       len(report.SBOM.Dependencies),
		VulnerabilityCount:    len(report.Vulnerabilities),
		SecretCount:           len(report.Secrets),
		MisconfigurationCount: len(report.Misconfigurations),
		IaCArtifactCount:      len(report.IaCArtifacts),
		MalwareCount:          len(report.Malware),
		TechnologyCount:       len(report.Technologies),
		Truncated:             inv.truncated,
	}
	report.Metadata["entries_visited"] = inv.entriesVisited
	if inv.truncated {
		report.Metadata["truncated"] = true
	}
	if len(inv.metadataErrors) > 0 {
		report.Metadata["errors"] = dedupeStrings(inv.metadataErrors)
	}
	return report, nil
}

type inventory struct {
	generatedAt    time.Time
	os             OSInfo
	packages       map[string]PackageRecord
	packageDeps    map[string]map[string]struct{}
	sbomComponents map[string]SBOMComponent
	sbomDeps       map[string]map[string]struct{}
	iacArtifactIDs map[string]struct{}
	secretKeys     map[string]struct{}
	technologyKeys map[string]struct{}
	npmGraphs      []npmDependencyGraph
	jsImports      map[string][]string
	goGraphs       []goDependencyGraph
	goImports      map[string][]string
	secrets        []SecretFinding
	configs        []ConfigFinding
	iacArtifacts   []IaCArtifact
	malware        []MalwareFinding
	technologies   []TechnologyRecord
	findings       []scanner.ContainerFinding
	entriesVisited int
	truncated      bool
	metadataErrors []string
}

func newInventory(now time.Time) *inventory {
	return &inventory{
		generatedAt:    now,
		packages:       make(map[string]PackageRecord),
		packageDeps:    make(map[string]map[string]struct{}),
		sbomComponents: make(map[string]SBOMComponent),
		sbomDeps:       make(map[string]map[string]struct{}),
		iacArtifactIDs: make(map[string]struct{}),
		secretKeys:     make(map[string]struct{}),
		technologyKeys: make(map[string]struct{}),
		jsImports:      make(map[string][]string),
		goImports:      make(map[string][]string),
	}
}

func (i *inventory) addPackages(pkgs ...PackageRecord) {
	for _, pkg := range pkgs {
		pkg.Name = strings.TrimSpace(pkg.Name)
		pkg.Version = strings.TrimSpace(pkg.Version)
		if pkg.Name == "" || pkg.Version == "" {
			continue
		}
		pkg.Ecosystem = strings.TrimSpace(pkg.Ecosystem)
		pkg.Manager = firstNonEmpty(pkg.Manager, pkg.Ecosystem)
		pkg.PURL = firstNonEmpty(pkg.PURL, buildPURL(pkg))
		key := packageInventoryKey(pkg)
		if existing, ok := i.packages[key]; ok {
			i.packages[key] = MergePackageRecord(existing, pkg)
			continue
		}
		i.packages[key] = pkg
	}
}

func (i *inventory) addNPMDependencyGraph(graph npmDependencyGraph) {
	if len(graph.Packages) > 0 {
		i.addPackages(graph.Packages...)
	}
	for parentKey, children := range graph.DependencyKeys {
		if _, ok := i.packageDeps[parentKey]; !ok {
			i.packageDeps[parentKey] = make(map[string]struct{})
		}
		for childKey := range children {
			i.packageDeps[parentKey][childKey] = struct{}{}
		}
	}
	i.npmGraphs = append(i.npmGraphs, graph)
}

func (i *inventory) addGoDependencyGraph(graph goDependencyGraph) {
	if len(graph.Packages) > 0 {
		i.addPackages(graph.Packages...)
	}
	if modulePath := strings.TrimSpace(graph.ModulePath); modulePath != "" {
		root := SBOMComponent{
			BOMRef:    sbomApplicationRef("golang", modulePath, graph.ManifestPath),
			Type:      "application",
			Name:      modulePath,
			Ecosystem: "golang",
			Location:  graph.ManifestPath,
		}
		i.sbomComponents[root.BOMRef] = root
		if len(graph.DirectKeys) > 0 {
			if _, ok := i.sbomDeps[root.BOMRef]; !ok {
				i.sbomDeps[root.BOMRef] = make(map[string]struct{})
			}
			for key := range graph.DirectKeys {
				pkg, ok := i.packages[key]
				if !ok {
					continue
				}
				i.sbomDeps[root.BOMRef][sbomComponentRef(pkg)] = struct{}{}
			}
		}
	}
	i.goGraphs = append(i.goGraphs, graph)
}

func (i *inventory) addJSImportFile(filePath string, imports []string) {
	if len(imports) == 0 {
		return
	}
	i.jsImports[filePath] = append(i.jsImports[filePath], imports...)
}

func (i *inventory) addGoImportFile(filePath string, imports []string) {
	if len(imports) == 0 {
		return
	}
	i.goImports[filePath] = append(i.goImports[filePath], imports...)
}

func (i *inventory) addSecrets(findings ...SecretFinding) {
	for _, finding := range findings {
		finding = normalizeSecretFinding(finding)
		key := secretFindingKey(finding)
		if _, ok := i.secretKeys[key]; ok {
			continue
		}
		i.secretKeys[key] = struct{}{}
		i.secrets = append(i.secrets, finding)
		i.findings = append(i.findings, scanner.ContainerFinding{
			ID:          finding.ID,
			Type:        "secret",
			Severity:    finding.Severity,
			Title:       "Potential secret detected",
			Description: firstNonEmpty(finding.Description, finding.Type),
			Remediation: "Remove persisted secrets and use dedicated secret injection mechanisms.",
		})
	}
}

func (i *inventory) addConfig(finding ConfigFinding) {
	i.configs = append(i.configs, finding)
	i.findings = append(i.findings, scanner.ContainerFinding{
		ID:          finding.ID,
		Type:        "misconfiguration",
		Severity:    finding.Severity,
		Title:       finding.Title,
		Description: finding.Description,
		Remediation: finding.Remediation,
	})
}

func (i *inventory) addConfigs(findings ...ConfigFinding) {
	for _, finding := range findings {
		i.addConfig(finding)
	}
}

func (i *inventory) addIaCArtifacts(artifacts ...IaCArtifact) {
	for _, artifact := range artifacts {
		artifact.ID = strings.TrimSpace(artifact.ID)
		artifact.Type = strings.TrimSpace(artifact.Type)
		artifact.Path = strings.TrimSpace(artifact.Path)
		if artifact.ID == "" || artifact.Type == "" || artifact.Path == "" {
			continue
		}
		if _, exists := i.iacArtifactIDs[artifact.ID]; exists {
			continue
		}
		i.iacArtifactIDs[artifact.ID] = struct{}{}
		i.iacArtifacts = append(i.iacArtifacts, artifact)
	}
}

func (i *inventory) addMalware(finding MalwareFinding) {
	i.malware = append(i.malware, finding)
	i.findings = append(i.findings, scanner.ContainerFinding{
		ID:          finding.ID,
		Type:        "malware",
		Severity:    finding.Severity,
		Title:       "Malware signature detected",
		Description: firstNonEmpty(finding.MalwareName, finding.MalwareType, "malicious artifact"),
		Remediation: "Quarantine the artifact, rotate credentials, and investigate provenance before redeploying.",
	})
}

func (i *inventory) addTechnologies(records ...TechnologyRecord) {
	for _, record := range records {
		record = normalizeTechnologyRecord(record)
		key := technologyKey(record)
		if key == "" {
			continue
		}
		if _, exists := i.technologyKeys[key]; exists {
			continue
		}
		i.technologyKeys[key] = struct{}{}
		i.technologies = append(i.technologies, record)
	}
}

func (i *inventory) sortedPackages() []PackageRecord {
	pkgs := make([]PackageRecord, 0, len(i.packages))
	for _, pkg := range i.packages {
		pkgs = append(pkgs, pkg)
	}
	sort.Slice(pkgs, func(a, b int) bool {
		left := pkgs[a]
		right := pkgs[b]
		if left.Ecosystem != right.Ecosystem {
			return left.Ecosystem < right.Ecosystem
		}
		if left.Name != right.Name {
			return left.Name < right.Name
		}
		if left.Version != right.Version {
			return left.Version < right.Version
		}
		return left.Location < right.Location
	})
	return pkgs
}

func (i *inventory) sortedSBOMDependencies() []SBOMDependency {
	depsByRef := make(map[string]map[string]struct{}, len(i.packageDeps)+len(i.sbomDeps))
	for parentKey, children := range i.packageDeps {
		parent, ok := i.packages[parentKey]
		if !ok {
			continue
		}
		parentRef := sbomComponentRef(parent)
		if _, ok := depsByRef[parentRef]; !ok {
			depsByRef[parentRef] = make(map[string]struct{})
		}
		for childKey := range children {
			child, ok := i.packages[childKey]
			if !ok {
				continue
			}
			depsByRef[parentRef][sbomComponentRef(child)] = struct{}{}
		}
	}
	for parentRef, children := range i.sbomDeps {
		if _, ok := depsByRef[parentRef]; !ok {
			depsByRef[parentRef] = make(map[string]struct{})
		}
		for childRef := range children {
			depsByRef[parentRef][childRef] = struct{}{}
		}
	}
	out := make([]SBOMDependency, 0, len(depsByRef))
	for parentRef, children := range depsByRef {
		dep := SBOMDependency{Ref: parentRef}
		for childRef := range children {
			dep.DependsOn = append(dep.DependsOn, childRef)
		}
		sort.Strings(dep.DependsOn)
		if len(dep.DependsOn) > 0 {
			out = append(out, dep)
		}
	}
	sort.Slice(out, func(a, b int) bool {
		return out[a].Ref < out[b].Ref
	})
	return out
}

func (i *inventory) sortedSBOMComponents(packages []PackageRecord) []SBOMComponent {
	components := make([]SBOMComponent, 0, len(packages)+len(i.sbomComponents))
	for _, pkg := range packages {
		components = append(components, SBOMComponent{
			BOMRef:           sbomComponentRef(pkg),
			Type:             "library",
			Name:             pkg.Name,
			Version:          pkg.Version,
			PURL:             pkg.PURL,
			Ecosystem:        pkg.Ecosystem,
			Location:         pkg.Location,
			DirectDependency: pkg.DirectDependency,
			Reachable:        pkg.Reachable,
			DependencyDepth:  pkg.DependencyDepth,
			ImportFileCount:  pkg.ImportFileCount,
		})
	}
	for _, component := range i.sbomComponents {
		components = append(components, component)
	}
	sort.Slice(components, func(a, b int) bool {
		return components[a].BOMRef < components[b].BOMRef
	})
	return components
}

func (i *inventory) sortedTechnologies() []TechnologyRecord {
	records := make([]TechnologyRecord, len(i.technologies))
	copy(records, i.technologies)
	sort.Slice(records, func(a, b int) bool {
		left := records[a]
		right := records[b]
		if left.Category != right.Category {
			return left.Category < right.Category
		}
		if left.Name != right.Name {
			return left.Name < right.Name
		}
		if left.Version != right.Version {
			return left.Version < right.Version
		}
		return left.Path < right.Path
	})
	return records
}

func (i *inventory) applyDependencyReachability() {
	npmBaseDirs := collectManifestBaseDirs(i.npmGraphs)
	for _, graph := range i.npmGraphs {
		reachable := make(map[string]map[string]struct{})
		for filePath, imports := range i.jsImports {
			if !manifestOwnsFile(filePath, graph.BaseDir, npmBaseDirs) {
				continue
			}
			for _, imp := range imports {
				for key := range graph.ImportableKeys[imp] {
					if _, ok := reachable[key]; !ok {
						reachable[key] = make(map[string]struct{})
					}
					reachable[key][filePath] = struct{}{}
				}
			}
		}
		type queueItem struct {
			key      string
			filePath string
		}
		queue := make([]queueItem, 0, len(reachable))
		for key, fileSet := range reachable {
			for filePath := range fileSet {
				queue = append(queue, queueItem{key: key, filePath: filePath})
			}
		}
		for len(queue) > 0 {
			current := queue[0]
			queue = queue[1:]
			pkg, ok := i.packages[current.key]
			if ok {
				pkg.Reachable = true
				pkg.ImportFileCount = max(pkg.ImportFileCount, len(reachable[current.key]))
				i.packages[current.key] = pkg
			}
			for child := range graph.DependencyKeys[current.key] {
				if _, ok := reachable[child]; !ok {
					reachable[child] = make(map[string]struct{})
				}
				if _, seen := reachable[child][current.filePath]; seen {
					continue
				}
				reachable[child][current.filePath] = struct{}{}
				queue = append(queue, queueItem{key: child, filePath: current.filePath})
			}
		}
	}
	goBaseDirs := collectManifestBaseDirs(i.goGraphs)
	for _, graph := range i.goGraphs {
		reachable := make(map[string]map[string]struct{})
		for filePath, imports := range i.goImports {
			if !manifestOwnsFile(filePath, graph.BaseDir, goBaseDirs) {
				continue
			}
			for _, imp := range imports {
				for _, key := range matchGoImportablePackageKeys(graph.ImportableKeys, imp) {
					if _, ok := reachable[key]; !ok {
						reachable[key] = make(map[string]struct{})
					}
					reachable[key][filePath] = struct{}{}
				}
			}
		}
		for key, fileSet := range reachable {
			pkg, ok := i.packages[key]
			if !ok {
				continue
			}
			pkg.Reachable = true
			pkg.ImportFileCount = max(pkg.ImportFileCount, len(fileSet))
			i.packages[key] = pkg
		}
	}
}

func (i *inventory) canonicalizeGraphBackedPackages() {
	if len(i.packages) == 0 {
		return
	}
	i.canonicalizeNPMGraphBackedPackages()
}

func (i *inventory) canonicalizeNPMGraphBackedPackages() {
	if len(i.npmGraphs) == 0 {
		return
	}
	baseDirs := collectManifestBaseDirs(i.npmGraphs)
	canonicalKeys := make(map[string]string, len(i.npmGraphs))
	manifestPaths := make(map[string]string, len(i.npmGraphs))
	for _, graph := range i.npmGraphs {
		manifestPaths[graph.BaseDir] = graph.ManifestPath
		for _, pkg := range graph.Packages {
			canonicalKeys[npmGraphCanonicalKey(graph.BaseDir, pkg.Name, pkg.Version)] = packageInventoryKey(pkg)
		}
	}
	for oldKey, pkg := range i.packages {
		if !isInstalledNPMPackageLocation(pkg.Location) {
			continue
		}
		baseDir := nearestManifestBaseDir(pkg.Location, baseDirs)
		manifestPath := manifestPaths[baseDir]
		if manifestPath == "" {
			continue
		}
		newKey := canonicalKeys[npmGraphCanonicalKey(baseDir, pkg.Name, pkg.Version)]
		if newKey == "" || newKey == oldKey {
			continue
		}
		existing, ok := i.packages[newKey]
		if !ok {
			continue
		}
		i.packages[newKey] = MergePackageRecord(existing, pkg)
		delete(i.packages, oldKey)
		i.remapPackageDependencyKey(oldKey, newKey)
	}
}

func npmGraphCanonicalKey(baseDir, name, version string) string {
	return strings.Join([]string{
		normalizeManifestBaseDir(baseDir),
		strings.TrimSpace(name),
		strings.TrimSpace(version),
	}, "|")
}

func isInstalledNPMPackageLocation(location string) bool {
	location = strings.TrimSpace(location)
	return strings.HasSuffix(location, "/package.json") && strings.Contains(location, "/node_modules/")
}

func (i *inventory) remapPackageDependencyKey(oldKey, newKey string) {
	if oldKey == "" || newKey == "" || oldKey == newKey {
		return
	}
	if children, ok := i.packageDeps[oldKey]; ok {
		if _, exists := i.packageDeps[newKey]; !exists {
			i.packageDeps[newKey] = make(map[string]struct{}, len(children))
		}
		for childKey := range children {
			if childKey == oldKey {
				childKey = newKey
			}
			i.packageDeps[newKey][childKey] = struct{}{}
		}
		delete(i.packageDeps, oldKey)
	}
	for parentKey, children := range i.packageDeps {
		if _, ok := children[oldKey]; !ok {
			continue
		}
		delete(children, oldKey)
		children[newKey] = struct{}{}
		if len(children) == 0 {
			delete(i.packageDeps, parentKey)
		}
	}
}

func collectManifestBaseDirs[T interface{ manifestBaseDir() string }](graphs []T) []string {
	seen := make(map[string]struct{}, len(graphs))
	out := make([]string, 0, len(graphs))
	for _, graph := range graphs {
		baseDir := normalizeManifestBaseDir(graph.manifestBaseDir())
		if _, ok := seen[baseDir]; ok {
			continue
		}
		seen[baseDir] = struct{}{}
		out = append(out, baseDir)
	}
	sort.Slice(out, func(i, j int) bool {
		return len(out[i]) > len(out[j])
	})
	return out
}

func manifestOwnsFile(filePath, baseDir string, manifestBaseDirs []string) bool {
	baseDir = normalizeManifestBaseDir(baseDir)
	filePath = strings.TrimSpace(filePath)
	if filePath == "" {
		return false
	}
	if !pathWithinManifestBase(filePath, baseDir) {
		return false
	}
	return nearestManifestBaseDir(filePath, manifestBaseDirs) == baseDir
}

func nearestManifestBaseDir(filePath string, manifestBaseDirs []string) string {
	filePath = strings.TrimSpace(filePath)
	if filePath == "" {
		return ""
	}
	for _, baseDir := range manifestBaseDirs {
		if pathWithinManifestBase(filePath, baseDir) {
			return baseDir
		}
	}
	return ""
}

func pathWithinManifestBase(filePath, baseDir string) bool {
	baseDir = normalizeManifestBaseDir(baseDir)
	filePath = strings.TrimSpace(filePath)
	if filePath == "" {
		return false
	}
	if baseDir == "" {
		return true
	}
	return filePath == baseDir || strings.HasPrefix(filePath, baseDir+"/")
}

func normalizeManifestBaseDir(baseDir string) string {
	baseDir = strings.TrimSpace(baseDir)
	if baseDir == "." {
		return ""
	}
	return baseDir
}

func readLimitedFile(root *os.Root, filePath string, limit int64) ([]byte, bool, error) {
	if root == nil {
		return nil, false, fmt.Errorf("filesystem root is nil")
	}
	if limit <= 0 {
		return nil, false, nil
	}
	file, err := root.Open(filePath)
	if err != nil {
		return nil, false, fmt.Errorf("open %s: %w", filePath, err)
	}
	defer func() { _ = file.Close() }()
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, false, fmt.Errorf("read %s: %w", filePath, err)
	}
	if int64(len(data)) > limit {
		return nil, false, nil
	}
	return data, true, nil
}

func shouldSkipDir(filePath, name string) bool {
	switch name {
	case ".git", ".hg", ".svn", ".terraform", ".venv", "venv", "__pycache__", "proc", "sys", "dev":
		return true
	}
	if strings.HasPrefix(filePath, "usr/lib/modules/") || strings.HasPrefix(filePath, "lib/modules/") {
		return true
	}
	return false
}

func shouldParsePackageFile(filePath string) bool {
	switch {
	case filePath == "etc/os-release", filePath == "etc/redhat-release", filePath == "etc/debian_version":
		return false
	case filePath == "var/lib/dpkg/status":
		return true
	case filePath == "lib/apk/db/installed":
		return true
	case strings.HasSuffix(filePath, ".dist-info/METADATA"):
		return true
	case strings.HasSuffix(filePath, ".egg-info/PKG-INFO"):
		return true
	case strings.HasSuffix(filePath, "/node_modules/package.json"):
		return true
	case strings.Contains(filePath, "/node_modules/") && strings.HasSuffix(filePath, "/package.json"):
		return true
	case path.Base(filePath) == "package-lock.json":
		return true
	case path.Base(filePath) == "npm-shrinkwrap.json":
		return true
	case path.Base(filePath) == "go.mod":
		return true
	case path.Base(filePath) == "go.sum":
		return true
	case path.Base(filePath) == "Cargo.lock":
		return true
	case path.Base(filePath) == "pom.xml":
		return true
	case path.Base(filePath) == "composer.lock":
		return true
	case path.Base(filePath) == "packages.config":
		return true
	default:
		return false
	}
}

func shouldParseOSFile(filePath string) bool {
	switch filePath {
	case "etc/os-release", "etc/redhat-release", "etc/debian_version":
		return true
	default:
		return false
	}
}

func shouldInspectJSImportFile(filePath string, mode fs.FileMode, size int64, maxBytes int64) bool {
	if mode&fs.ModeSymlink != 0 || mode.IsDir() || size <= 0 || size > maxBytes {
		return false
	}
	if pathHasSegment(filePath, "node_modules") || pathHasSegment(filePath, "vendor") || pathHasSegment(filePath, "dist") || pathHasSegment(filePath, "build") {
		return false
	}
	switch strings.ToLower(path.Ext(filePath)) {
	case ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs":
		return true
	default:
		return false
	}
}

func shouldInspectGoImportFile(filePath string, mode fs.FileMode, size int64, maxBytes int64) bool {
	if mode&fs.ModeSymlink != 0 || mode.IsDir() || size <= 0 || size > maxBytes {
		return false
	}
	if pathHasSegment(filePath, "vendor") || pathHasSegment(filePath, "testdata") || pathHasSegment(filePath, "fixtures") {
		return false
	}
	return strings.EqualFold(path.Ext(filePath), ".go")
}

func shouldInspectPEBinary(filePath string, mode fs.FileMode, size int64, maxBytes int64) bool {
	if mode&fs.ModeSymlink != 0 || mode.IsDir() || size <= 0 || size > maxBytes {
		return false
	}
	switch strings.ToLower(path.Ext(strings.TrimSpace(filePath))) {
	case ".dll", ".exe", ".sys", ".ocx", ".scr", ".cpl":
		return true
	default:
		return false
	}
}

func pathHasSegment(filePath, segment string) bool {
	filePath = strings.Trim(strings.TrimSpace(filePath), "/")
	segment = strings.Trim(strings.TrimSpace(segment), "/")
	if filePath == "" || segment == "" {
		return false
	}
	parts := strings.Split(filePath, "/")
	for _, part := range parts {
		if part == segment {
			return true
		}
	}
	return false
}

func shouldParseConfigFile(filePath string) bool {
	if filePath == "etc/ssh/sshd_config" {
		return true
	}
	if filePath == "etc/sudoers" || strings.HasPrefix(filePath, "etc/sudoers.d/") {
		return true
	}
	if strings.HasPrefix(filePath, "etc/cron.") || strings.HasPrefix(filePath, "etc/cron/") || strings.HasPrefix(filePath, "var/spool/cron/") {
		return true
	}
	return false
}

func shouldInspectIaCFile(filePath string, mode fs.FileMode, size int64, maxBytes int64) bool {
	if mode&fs.ModeSymlink != 0 || mode.IsDir() || size <= 0 || size > maxBytes {
		return false
	}
	if strings.Contains(filePath, "/testdata/") || strings.Contains(filePath, "/fixtures/") || strings.Contains(filePath, "/examples/") {
		return false
	}
	lowerPath := strings.ToLower(strings.TrimSpace(filePath))
	base := path.Base(lowerPath)
	switch {
	case strings.HasSuffix(lowerPath, ".tf"),
		strings.HasSuffix(lowerPath, ".tfvars"),
		strings.HasSuffix(lowerPath, ".tfstate"),
		strings.HasSuffix(lowerPath, ".tfstate.backup"),
		strings.HasSuffix(lowerPath, ".template"):
		return true
	}
	switch base {
	case "dockerfile", "docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml",
		"chart.yaml", "values.yaml", "playbook.yml", "playbook.yaml", "site.yml", "site.yaml",
		"inventory", ".env", "config.json", "application.properties", "ansible.cfg":
		return true
	}
	ext := strings.ToLower(path.Ext(lowerPath))
	switch ext {
	case ".yaml", ".yml", ".json":
		return true
	default:
		return false
	}
}

func shouldSecretScan(filePath string, mode fs.FileMode, size int64, maxBytes int64) bool {
	if mode&fs.ModeSymlink != 0 || mode.IsDir() || size <= 0 || size > maxBytes {
		return false
	}
	if strings.Contains(filePath, "/testdata/") || strings.Contains(filePath, "/fixtures/") || strings.Contains(filePath, "/examples/") {
		return false
	}
	for _, segment := range []string{"/node_modules/", "/vendor/", "/site-packages/", "/dist-packages/", ".dist-info/", ".egg-info/", "/.git/"} {
		if strings.Contains(filePath, segment) {
			return false
		}
	}
	ext := strings.ToLower(path.Ext(filePath))
	switch ext {
	case ".env", ".ini", ".cfg", ".conf", ".yaml", ".yml", ".json", ".xml", ".toml", ".properties", ".sh", ".bashrc", ".zshrc", ".py", ".js", ".ts", ".go", ".java", ".rb", ".php", ".ps1", ".cs", ".pem", ".key", ".txt":
		return true
	}
	base := path.Base(filePath)
	switch base {
	case ".env", ".envrc", "config", "authorized_keys", "known_hosts", ".bash_history", ".zsh_history", "credentials", "secrets", "Dockerfile", "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "application.properties":
		return true
	}
	return ext == ""
}

func shouldMalwareScan(filePath string, mode fs.FileMode, size int64, maxBytes int64) bool {
	if maxBytes <= 0 {
		maxBytes = defaultMaxMalwareBytes
	}
	if mode.IsDir() || mode&fs.ModeSymlink != 0 || size <= 0 || size > maxBytes {
		return false
	}
	if mode&0o111 != 0 {
		return true
	}
	ext := strings.ToLower(path.Ext(filePath))
	switch ext {
	case ".sh", ".py", ".js", ".php", ".rb", ".pl", ".ps1", ".jar", ".war", ".bin", ".so", ".dll", ".exe", ".com", ".bat", ".cmd", ".scr":
		return true
	default:
		return false
	}
}

func shouldIgnoreWorldWritablePath(filePath string) bool {
	switch filePath {
	case "tmp", "var/tmp", "dev/shm":
		return true
	default:
		return false
	}
}

func isWorldWritableDir(mode fs.FileMode, filePath string) bool {
	return mode.IsDir() && mode.Perm()&0o002 != 0 && !shouldIgnoreWorldWritablePath(filePath)
}

func parseOSInfo(filePath string, data []byte) OSInfo {
	filePath = strings.TrimSpace(filePath)
	switch filePath {
	case "etc/os-release":
		values := make(map[string]string)
		scanner := bufio.NewScanner(bytes.NewReader(data))
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			key, value, ok := strings.Cut(line, "=")
			if !ok {
				continue
			}
			values[strings.TrimSpace(key)] = strings.Trim(strings.TrimSpace(value), `"`)
		}
		return OSInfo{
			ID:         values["ID"],
			Name:       firstNonEmpty(values["NAME"], values["ID"]),
			PrettyName: firstNonEmpty(values["PRETTY_NAME"], values["NAME"]),
			Version:    firstNonEmpty(values["VERSION"], values["VERSION_ID"]),
			VersionID:  values["VERSION_ID"],
			Family:     firstNonEmpty(values["ID_LIKE"], values["ID"]),
		}
	case "etc/redhat-release":
		text := strings.TrimSpace(string(data))
		return OSInfo{Name: "Red Hat", PrettyName: text, Version: text, Family: "rhel"}
	case "etc/debian_version":
		text := strings.TrimSpace(string(data))
		return OSInfo{ID: "debian", Name: "Debian", PrettyName: "Debian " + text, Version: text, VersionID: text, Family: "debian"}
	default:
		return OSInfo{}
	}
}

func mergeOSInfo(dst *OSInfo, src OSInfo) {
	if dst == nil {
		return
	}
	dst.ID = firstNonEmpty(dst.ID, src.ID)
	dst.Name = firstNonEmpty(dst.Name, src.Name)
	dst.PrettyName = firstNonEmpty(dst.PrettyName, src.PrettyName)
	dst.Version = firstNonEmpty(dst.Version, src.Version)
	dst.VersionID = firstNonEmpty(dst.VersionID, src.VersionID)
	dst.Family = firstNonEmpty(dst.Family, src.Family)
	dst.Architecture = firstNonEmpty(dst.Architecture, src.Architecture)
}

func parsePackageRecords(filePath string, data []byte) []PackageRecord {
	switch {
	case filePath == "var/lib/dpkg/status":
		return parseDPKGStatus(filePath, data)
	case filePath == "lib/apk/db/installed":
		return parseAPKInstalled(filePath, data)
	case strings.HasSuffix(filePath, ".dist-info/METADATA") || strings.HasSuffix(filePath, ".egg-info/PKG-INFO"):
		return parsePythonMetadata(filePath, data)
	case strings.HasSuffix(filePath, "/package.json") && strings.Contains(filePath, "/node_modules/"):
		return parseNPMPackage(filePath, data)
	case path.Base(filePath) == "go.sum":
		return parseGoSum(filePath, data)
	case path.Base(filePath) == "Cargo.lock":
		return parseCargoLock(filePath, data)
	case path.Base(filePath) == "pom.xml":
		return parsePOM(filePath, data)
	case path.Base(filePath) == "composer.lock":
		return parseComposerLock(filePath, data)
	case path.Base(filePath) == "packages.config":
		return parsePackagesConfig(filePath, data)
	default:
		return nil
	}
}

func inspectPEBinary(filePath string, data []byte) (*PackageRecord, []ConfigFinding, OSInfo, error) {
	if !looksLikePEBinary(data) {
		return nil, nil, OSInfo{}, nil
	}
	file, err := pe.NewFile(bytes.NewReader(data))
	if err != nil {
		return nil, nil, OSInfo{}, fmt.Errorf("parse PE %s: %w", filePath, err)
	}
	defer func() { _ = file.Close() }()

	version := peBinaryVersion(file)
	if version == "" {
		version = "0.0.0.0"
	}
	pkg := &PackageRecord{
		Ecosystem: "windows",
		Manager:   "pe",
		Name:      path.Base(filePath),
		Version:   version,
		Location:  filePath,
	}

	osInfo := inferWindowsOSInfo(filePath, version, peMachineArchitecture(file.Machine))
	signed, sigErr := hasEmbeddedPEAuthenticodeSignature(file, data)
	findings := make([]ConfigFinding, 0, 1)
	if sigErr != nil {
		findings = append(findings, ConfigFinding{
			ID:           findingID("binary_signature", filePath),
			Type:         "binary_signature",
			Severity:     "high",
			Path:         filePath,
			Title:        "Windows PE signature metadata is invalid",
			Description:  firstNonEmpty(sigErr.Error(), "PE binary has invalid Authenticode metadata."),
			Remediation:  "Rebuild or replace the binary with a trusted Authenticode-signed artifact.",
			ResourceType: "binary",
			ArtifactType: "windows_pe",
			Format:       "pe",
		})
	} else if !signed {
		findings = append(findings, ConfigFinding{
			ID:           findingID("binary_signature", filePath),
			Type:         "binary_signature",
			Severity:     "medium",
			Path:         filePath,
			Title:        "Windows PE binary is unsigned",
			Description:  "PE binary does not contain an embedded Authenticode signature.",
			Remediation:  "Prefer Authenticode-signed binaries and verify signatures before deployment.",
			ResourceType: "binary",
			ArtifactType: "windows_pe",
			Format:       "pe",
		})
	}
	return pkg, findings, osInfo, nil
}

func looksLikePEBinary(data []byte) bool {
	if len(data) < 0x40 || string(data[:2]) != "MZ" {
		return false
	}
	peOffset := int(binary.LittleEndian.Uint32(data[0x3c:]))
	if peOffset < 0 || peOffset+4 > len(data) {
		return false
	}
	return bytes.Equal(data[peOffset:peOffset+4], []byte("PE\x00\x00"))
}

func peBinaryVersion(file *pe.File) string {
	if file == nil {
		return ""
	}
	switch header := file.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		return formatWindowsVersion(header.MajorOperatingSystemVersion, header.MinorOperatingSystemVersion, header.MajorImageVersion, header.MinorImageVersion)
	case *pe.OptionalHeader64:
		return formatWindowsVersion(header.MajorOperatingSystemVersion, header.MinorOperatingSystemVersion, header.MajorImageVersion, header.MinorImageVersion)
	default:
		return ""
	}
}

func formatWindowsVersion(majorOS, minorOS, majorImage, minorImage uint16) string {
	if majorOS == 0 && minorOS == 0 && majorImage == 0 && minorImage == 0 {
		return ""
	}
	return fmt.Sprintf("%d.%d.%d.%d", majorOS, minorOS, majorImage, minorImage)
}

func inferWindowsOSInfo(filePath, version, architecture string) OSInfo {
	lowerPath := strings.ToLower(strings.TrimSpace(filePath))
	if !strings.HasPrefix(lowerPath, "windows/") && !strings.Contains(lowerPath, "/windows/") {
		return OSInfo{}
	}
	info := OSInfo{
		ID:           "windows",
		Name:         "Windows",
		PrettyName:   "Windows",
		Family:       "windows",
		Architecture: architecture,
	}
	if strings.Contains(lowerPath, "windows/system32/") || strings.Contains(lowerPath, "windows/syswow64/") {
		info.Version = version
		info.VersionID = version
	}
	return info
}

func peMachineArchitecture(machine uint16) string {
	switch machine {
	case 0x14c:
		return "386"
	case 0x8664:
		return "amd64"
	case 0xaa64:
		return "arm64"
	default:
		return ""
	}
}

func hasEmbeddedPEAuthenticodeSignature(file *pe.File, data []byte) (bool, error) {
	offset, size, ok := peSecurityDirectory(file)
	if !ok || size == 0 {
		return false, nil
	}
	if offset == 0 || size < 8 {
		return false, fmt.Errorf("invalid Authenticode certificate table header")
	}
	end := uint64(offset) + uint64(size)
	if end > uint64(len(data)) {
		return false, fmt.Errorf("invalid Authenticode certificate table bounds")
	}
	cert := data[offset:end]
	declaredSize := binary.LittleEndian.Uint32(cert[:4])
	if declaredSize < 8 || uint64(declaredSize) > uint64(size) {
		return false, fmt.Errorf("invalid Authenticode certificate table size")
	}
	return true, nil
}

func peSecurityDirectory(file *pe.File) (uint32, uint32, bool) {
	if file == nil {
		return 0, 0, false
	}
	switch header := file.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		entry := header.DataDirectory[4]
		return entry.VirtualAddress, entry.Size, true
	case *pe.OptionalHeader64:
		entry := header.DataDirectory[4]
		return entry.VirtualAddress, entry.Size, true
	default:
		return 0, 0, false
	}
}

func parseDPKGStatus(filePath string, data []byte) []PackageRecord {
	blocks := strings.Split(string(data), "\n\n")
	pkgs := make([]PackageRecord, 0)
	for _, block := range blocks {
		var name, version string
		for _, line := range strings.Split(block, "\n") {
			if strings.HasPrefix(line, "Package: ") {
				name = strings.TrimSpace(strings.TrimPrefix(line, "Package: "))
			}
			if strings.HasPrefix(line, "Version: ") {
				version = strings.TrimSpace(strings.TrimPrefix(line, "Version: "))
			}
		}
		if name != "" && version != "" {
			pkgs = append(pkgs, PackageRecord{Ecosystem: "deb", Manager: "dpkg", Name: name, Version: version, Location: filePath})
		}
	}
	return pkgs
}

func parseAPKInstalled(filePath string, data []byte) []PackageRecord {
	blocks := strings.Split(string(data), "\n\n")
	pkgs := make([]PackageRecord, 0)
	for _, block := range blocks {
		var name, version string
		for _, line := range strings.Split(block, "\n") {
			switch {
			case strings.HasPrefix(line, "P:"):
				name = strings.TrimSpace(strings.TrimPrefix(line, "P:"))
			case strings.HasPrefix(line, "V:"):
				version = strings.TrimSpace(strings.TrimPrefix(line, "V:"))
			}
		}
		if name != "" && version != "" {
			pkgs = append(pkgs, PackageRecord{Ecosystem: "apk", Manager: "apk", Name: name, Version: version, Location: filePath})
		}
	}
	return pkgs
}

func parsePythonMetadata(filePath string, data []byte) []PackageRecord {
	var name, version string
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case strings.HasPrefix(line, "Name: "):
			name = strings.TrimSpace(strings.TrimPrefix(line, "Name: "))
		case strings.HasPrefix(line, "Version: "):
			version = strings.TrimSpace(strings.TrimPrefix(line, "Version: "))
		}
	}
	if name == "" || version == "" {
		return nil
	}
	return []PackageRecord{{Ecosystem: "pypi", Manager: "pip", Name: name, Version: version, Location: filePath}}
}

func parseNPMPackage(filePath string, data []byte) []PackageRecord {
	var pkg struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	}
	if err := json.Unmarshal(data, &pkg); err != nil {
		return nil
	}
	if strings.TrimSpace(pkg.Name) == "" || strings.TrimSpace(pkg.Version) == "" {
		return nil
	}
	return []PackageRecord{{Ecosystem: "npm", Manager: "npm", Name: pkg.Name, Version: pkg.Version, Location: filePath}}
}

func parseGoSum(filePath string, data []byte) []PackageRecord {
	seen := make(map[string]struct{})
	pkgs := make([]PackageRecord, 0)
	location := strings.TrimSpace(filePath)
	if path.Base(location) == "go.sum" {
		location = path.Join(path.Dir(location), "go.mod")
	}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		parts := strings.Fields(scanner.Text())
		if len(parts) < 2 {
			continue
		}
		name := strings.TrimSpace(parts[0])
		version := strings.TrimSuffix(strings.TrimSpace(parts[1]), "/go.mod")
		if name == "" || version == "" {
			continue
		}
		key := name + "@" + version
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		pkgs = append(pkgs, PackageRecord{Ecosystem: "golang", Manager: "go", Name: name, Version: version, Location: location})
	}
	return pkgs
}

func parseCargoLock(filePath string, data []byte) []PackageRecord {
	pkgs := make([]PackageRecord, 0)
	var name, version string
	scanner := bufio.NewScanner(bytes.NewReader(data))
	flush := func() {
		if name != "" && version != "" {
			pkgs = append(pkgs, PackageRecord{Ecosystem: "cargo", Manager: "cargo", Name: name, Version: version, Location: filePath})
		}
		name = ""
		version = ""
	}
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "[[package]]" {
			flush()
			continue
		}
		if strings.HasPrefix(line, "name = ") {
			name = strings.Trim(strings.TrimSpace(strings.TrimPrefix(line, "name = ")), `"`)
		}
		if strings.HasPrefix(line, "version = ") {
			version = strings.Trim(strings.TrimSpace(strings.TrimPrefix(line, "version = ")), `"`)
		}
	}
	flush()
	return pkgs
}

func parsePOM(filePath string, data []byte) []PackageRecord {
	type dependency struct {
		GroupID    string `xml:"groupId"`
		ArtifactID string `xml:"artifactId"`
		Version    string `xml:"version"`
	}
	type project struct {
		Dependencies []dependency `xml:"dependencies>dependency"`
	}
	var pom project
	if err := xml.Unmarshal(data, &pom); err != nil {
		return nil
	}
	pkgs := make([]PackageRecord, 0, len(pom.Dependencies))
	for _, dep := range pom.Dependencies {
		name := strings.Trim(strings.TrimSpace(dep.GroupID)+":"+strings.TrimSpace(dep.ArtifactID), ":")
		version := strings.TrimSpace(dep.Version)
		if name == "" || version == "" {
			continue
		}
		pkgs = append(pkgs, PackageRecord{Ecosystem: "maven", Manager: "maven", Name: name, Version: version, Location: filePath})
	}
	return pkgs
}

func parseComposerLock(filePath string, data []byte) []PackageRecord {
	var lock struct {
		Packages []struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"packages"`
	}
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil
	}
	pkgs := make([]PackageRecord, 0, len(lock.Packages))
	for _, pkg := range lock.Packages {
		if strings.TrimSpace(pkg.Name) == "" || strings.TrimSpace(pkg.Version) == "" {
			continue
		}
		pkgs = append(pkgs, PackageRecord{Ecosystem: "composer", Manager: "composer", Name: pkg.Name, Version: pkg.Version, Location: filePath})
	}
	return pkgs
}

func parsePackagesConfig(filePath string, data []byte) []PackageRecord {
	type pkg struct {
		ID      string `xml:"id,attr"`
		Version string `xml:"version,attr"`
	}
	type config struct {
		Packages []pkg `xml:"package"`
	}
	var cfg config
	if err := xml.Unmarshal(data, &cfg); err != nil {
		return nil
	}
	pkgs := make([]PackageRecord, 0, len(cfg.Packages))
	for _, pkg := range cfg.Packages {
		if strings.TrimSpace(pkg.ID) == "" || strings.TrimSpace(pkg.Version) == "" {
			continue
		}
		pkgs = append(pkgs, PackageRecord{Ecosystem: "nuget", Manager: "nuget", Name: pkg.ID, Version: pkg.Version, Location: filePath})
	}
	return pkgs
}

func parseConfigFindings(filePath string, data []byte) []ConfigFinding {
	findings := make([]ConfigFinding, 0)
	text := string(data)
	switch {
	case filePath == "etc/ssh/sshd_config":
		if hasEnabledDirective(text, "PermitRootLogin") {
			findings = append(findings, ConfigFinding{
				ID:          findingID("ssh_permit_root_login", filePath),
				Type:        "ssh",
				Severity:    "high",
				Path:        filePath,
				Title:       "SSH root login enabled",
				Description: "sshd_config allows direct root login.",
				Remediation: "Set PermitRootLogin no and use scoped administrative accounts.",
			})
		}
		if hasEnabledDirective(text, "PasswordAuthentication") {
			findings = append(findings, ConfigFinding{
				ID:          findingID("ssh_password_auth", filePath),
				Type:        "ssh",
				Severity:    "medium",
				Path:        filePath,
				Title:       "SSH password authentication enabled",
				Description: "sshd_config allows password-based logins.",
				Remediation: "Disable PasswordAuthentication and require stronger interactive auth controls.",
			})
		}
	case filePath == "etc/sudoers" || strings.HasPrefix(filePath, "etc/sudoers.d/"):
		if strings.Contains(text, "NOPASSWD") {
			findings = append(findings, ConfigFinding{
				ID:          findingID("sudo_nopasswd", filePath),
				Type:        "sudo",
				Severity:    "high",
				Path:        filePath,
				Title:       "Passwordless sudo rule",
				Description: "sudoers configuration grants NOPASSWD privileges.",
				Remediation: "Require authentication for sudo or scope passwordless rules tightly to audited commands.",
			})
		}
		if strings.Contains(text, "ALL=(ALL) ALL") {
			findings = append(findings, ConfigFinding{
				ID:          findingID("sudo_all_all", filePath),
				Type:        "sudo",
				Severity:    "medium",
				Path:        filePath,
				Title:       "Broad sudo entitlement",
				Description: "sudoers configuration grants unrestricted sudo access.",
				Remediation: "Reduce sudo permissions to the minimum required command set.",
			})
		}
	case strings.HasPrefix(filePath, "etc/cron") || strings.HasPrefix(filePath, "var/spool/cron/"):
		for _, line := range strings.Split(text, "\n") {
			trimmed := strings.TrimSpace(line)
			if trimmed == "" || strings.HasPrefix(trimmed, "#") {
				continue
			}
			if strings.Contains(trimmed, "/tmp/") || strings.Contains(trimmed, "/var/tmp/") {
				findings = append(findings, ConfigFinding{
					ID:          findingID("cron_writable_script", filePath),
					Type:        "cron",
					Severity:    "high",
					Path:        filePath,
					Title:       "Cron job references writable path",
					Description: "Cron entry executes content from a writable temporary directory.",
					Remediation: "Move scheduled scripts into controlled, non-world-writable paths.",
				})
				break
			}
		}
	}
	return findings
}

func inspectIaCFile(filePath string, data []byte) ([]IaCArtifact, []ConfigFinding) {
	if looksBinary(data) {
		return nil, nil
	}
	artifacts := detectIaCArtifacts(filePath, data)
	findings := parseIaCFindings(filePath, data, artifacts)
	return artifacts, findings
}

func detectIaCArtifacts(filePath string, data []byte) []IaCArtifact {
	lowerPath := strings.ToLower(strings.TrimSpace(filePath))
	base := path.Base(lowerPath)
	ext := strings.ToLower(path.Ext(lowerPath))
	format := "text"
	switch ext {
	case ".tf", ".tfvars":
		format = "hcl"
	case ".yaml", ".yml", ".template":
		format = "yaml"
	case ".json", ".tfstate", ".backup":
		format = "json"
	case ".properties":
		format = "properties"
	}

	artifacts := make([]IaCArtifact, 0, 1)
	appendArtifact := func(kind, artifactFormat, resourceType string) {
		kind = strings.TrimSpace(kind)
		if kind == "" {
			return
		}
		if artifactFormat == "" {
			artifactFormat = format
		}
		artifacts = append(artifacts, IaCArtifact{
			ID:           findingID("iac_artifact", kind+":"+filePath),
			Type:         kind,
			Path:         filePath,
			Format:       artifactFormat,
			ResourceType: strings.TrimSpace(resourceType),
		})
	}

	switch {
	case strings.HasSuffix(lowerPath, ".tf"):
		appendArtifact("terraform", "hcl", inferIaCResourceType(lowerPath, string(data)))
	case strings.HasSuffix(lowerPath, ".tfvars"):
		appendArtifact("terraform_variables", "hcl", "")
	case strings.HasSuffix(lowerPath, ".tfstate"), strings.HasSuffix(lowerPath, ".tfstate.backup"):
		appendArtifact("terraform_state", "json", "terraform_state")
	case base == "dockerfile":
		appendArtifact("dockerfile", "dockerfile", "container_image")
	case base == "docker-compose.yml" || base == "docker-compose.yaml" || base == "compose.yml" || base == "compose.yaml":
		appendArtifact("docker_compose", "yaml", "container_service")
	case base == "chart.yaml":
		appendArtifact("helm_chart", "yaml", "helm_chart")
	case base == "values.yaml":
		appendArtifact("helm_values", "yaml", "")
	case base == "playbook.yml" || base == "playbook.yaml" || base == "site.yml" || base == "site.yaml" || base == "inventory" || base == "ansible.cfg" || strings.Contains(lowerPath, "/roles/"):
		appendArtifact("ansible", format, "configuration")
	case base == ".env":
		appendArtifact("environment_file", "env", "configuration")
	case base == "config.json":
		appendArtifact("json_config", "json", "configuration")
	case base == "application.properties":
		appendArtifact("application_properties", "properties", "configuration")
	default:
		text := string(data)
		lowerText := strings.ToLower(text)
		switch {
		case strings.Contains(text, "AWSTemplateFormatVersion"):
			appendArtifact("cloudformation", format, inferIaCResourceType(lowerPath, text))
		case strings.Contains(text, "apiVersion:") && strings.Contains(text, "kind:"):
			appendArtifact("kubernetes_manifest", format, inferIaCResourceType(lowerPath, text))
		case strings.Contains(lowerPath, "/templates/") && (ext == ".yaml" || ext == ".yml"):
			appendArtifact("helm_template", "yaml", inferIaCResourceType(lowerPath, text))
		case ext == ".json" && (strings.Contains(lowerText, "\"resources\"") || strings.Contains(lowerText, "\"terraform_version\"")):
			appendArtifact("terraform_json", "json", inferIaCResourceType(lowerPath, text))
		}
	}
	return artifacts
}

func parseIaCFindings(filePath string, data []byte, artifacts []IaCArtifact) []ConfigFinding {
	if len(artifacts) == 0 {
		return nil
	}
	text := string(data)
	lowerText := strings.ToLower(text)
	resourceType := ""
	artifactType := ""
	format := ""
	for _, artifact := range artifacts {
		resourceType = firstNonEmpty(resourceType, artifact.ResourceType)
		artifactType = firstNonEmpty(artifactType, artifact.Type)
		format = firstNonEmpty(format, artifact.Format)
	}

	findings := make([]ConfigFinding, 0, 3)
	appendFinding := func(kind, severity, title, description, remediation, findingResourceType string) {
		findings = append(findings, ConfigFinding{
			ID:           findingID(kind, filePath),
			Type:         kind,
			Severity:     severity,
			Path:         filePath,
			Title:        title,
			Description:  description,
			Remediation:  remediation,
			ResourceType: firstNonEmpty(findingResourceType, resourceType),
			ArtifactType: artifactType,
			Format:       format,
		})
	}

	if artifactType == "terraform_state" {
		appendFinding(
			"terraform_state",
			"high",
			"Terraform state file detected",
			"Terraform state frequently persists provider credentials, infrastructure metadata, and plaintext secrets.",
			"Remove state files from deployed artifacts and store state only in encrypted remote backends with access controls.",
			"terraform_state",
		)
	}

	if hasIaCPublicExposure(lowerText) {
		appendFinding(
			"iac_public_exposure",
			"high",
			"Public network exposure in IaC or config",
			"IaC or configuration content allows unrestricted ingress or public exposure.",
			"Replace public CIDRs or principals with scoped identities, private networking, or tightly bounded ranges.",
			firstNonEmpty(inferPublicExposureResourceType(lowerText), resourceType),
		)
	}

	if hasPublicStorageExposure(lowerText) {
		appendFinding(
			"iac_public_storage",
			"high",
			"Public storage access configured",
			"Template or configuration grants public read access to storage resources.",
			"Remove public principals and ACLs, then require authenticated access through scoped identities or signed requests.",
			"bucket",
		)
	}

	if supportsBucketEncryptionCheck(artifactType) && missingBucketEncryption(lowerText) {
		appendFinding(
			"iac_missing_bucket_encryption",
			"medium",
			"Bucket definition missing encryption setting",
			"Storage bucket configuration is present without an explicit encryption setting.",
			"Enable provider-managed encryption or a customer-managed KMS key in the IaC definition.",
			"bucket",
		)
	}

	return findings
}

func supportsBucketEncryptionCheck(artifactType string) bool {
	switch strings.TrimSpace(artifactType) {
	case "terraform", "terraform_json", "cloudformation":
		return true
	default:
		return false
	}
}

func inferIaCResourceType(filePath, text string) string {
	lowerText := strings.ToLower(text)
	switch {
	case strings.Contains(lowerText, "aws_security_group"), strings.Contains(lowerText, "google_compute_firewall"), strings.Contains(lowerText, "networksecuritygroup"):
		return "firewall_rule"
	case strings.Contains(lowerText, "aws_s3_bucket"), strings.Contains(lowerText, "google_storage_bucket"), strings.Contains(lowerText, "azurerm_storage_account"), strings.Contains(lowerText, "aws::s3::bucket"):
		return "bucket"
	case strings.Contains(lowerText, "kind: service"), strings.Contains(lowerText, "kind: ingress"), strings.Contains(lowerText, "kind: networkpolicy"):
		return "kubernetes_network"
	case strings.Contains(strings.ToLower(filePath), "dockerfile"), strings.Contains(lowerText, "services:"):
		return "container_service"
	default:
		return ""
	}
}

func hasIaCPublicExposure(lowerText string) bool {
	return strings.Contains(lowerText, "0.0.0.0/0") ||
		strings.Contains(lowerText, "::/0") ||
		strings.Contains(lowerText, "\"cidr\": \"0.0.0.0/0\"") ||
		strings.Contains(lowerText, "host: 0.0.0.0") ||
		strings.Contains(lowerText, "listen_address=0.0.0.0") ||
		strings.Contains(lowerText, "source_ranges") && strings.Contains(lowerText, "0.0.0.0/0")
}

func hasPublicStorageExposure(lowerText string) bool {
	return strings.Contains(lowerText, "allusers") ||
		strings.Contains(lowerText, "allauthenticatedusers") ||
		strings.Contains(lowerText, "public-read") ||
		strings.Contains(lowerText, "\"principal\": \"*\"") && strings.Contains(lowerText, "s3:getobject")
}

func inferPublicExposureResourceType(lowerText string) string {
	switch {
	case strings.Contains(lowerText, "aws_security_group"), strings.Contains(lowerText, "google_compute_firewall"), strings.Contains(lowerText, "networksecuritygroup"), strings.Contains(lowerText, "source_ranges"):
		return "firewall_rule"
	case strings.Contains(lowerText, "kind: service"), strings.Contains(lowerText, "kind: ingress"):
		return "kubernetes_service"
	default:
		return ""
	}
}

func missingBucketEncryption(lowerText string) bool {
	hasBucket := strings.Contains(lowerText, "aws_s3_bucket") ||
		strings.Contains(lowerText, "google_storage_bucket") ||
		strings.Contains(lowerText, "aws::s3::bucket")
	if !hasBucket {
		return false
	}
	return !strings.Contains(lowerText, "server_side_encryption_configuration") &&
		!strings.Contains(lowerText, "bucketencryption") &&
		!strings.Contains(lowerText, "default_kms_key_name") &&
		!strings.Contains(lowerText, "kms_key_name") &&
		!strings.Contains(lowerText, "encryption")
}

func scanSecrets(filePath string, data []byte) []SecretFinding {
	if looksBinary(data) {
		return nil
	}
	findings := make([]SecretFinding, 0)
	seen := make(map[string]struct{})
	appendFinding := func(kind, severity, match, description string, lineNo int, refs ...SecretReference) {
		id := findingID(kind, fmt.Sprintf("%s:%d:%s", filePath, lineNo, match))
		if _, ok := seen[id]; ok {
			return
		}
		seen[id] = struct{}{}
		finding := SecretFinding{
			ID:          id,
			Type:        kind,
			Severity:    severity,
			Path:        filePath,
			Line:        lineNo,
			Match:       match,
			Description: description,
		}
		if len(refs) > 0 {
			finding.References = append([]SecretReference(nil), refs...)
		}
		findings = append(findings, finding)
	}
	if ref, ok := gcpServiceAccountKeyReference(data); ok {
		appendFinding(
			"gcp_service_account_key",
			"critical",
			fingerprintSecretMatch(ref.Identifier+"|"+ref.Attributes["private_key_id"]),
			"Potential GCP service account key detected.",
			1,
			ref,
		)
	}
	for _, finding := range dockerConfigSecretFindings(filePath, data) {
		appendFinding(finding.Type, finding.Severity, finding.Match, finding.Description, finding.Line, finding.References...)
	}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		matchedSpecificSecret := false
		for _, match := range awsAccessKeyPattern.FindAllString(line, -1) {
			matchedSpecificSecret = true
			appendFinding(
				"aws_access_key",
				"critical",
				fingerprintSecretMatch(match),
				"Potential AWS access key detected.",
				lineNo,
				SecretReference{Kind: "cloud_identity", Provider: "aws", Identifier: strings.TrimSpace(match)},
			)
		}
		for _, match := range githubTokenPattern.FindAllString(line, -1) {
			matchedSpecificSecret = true
			appendFinding("github_token", "high", fingerprintSecretMatch(match), "Potential GitHub token detected.", lineNo)
		}
		for _, match := range gitlabTokenPattern.FindAllString(line, -1) {
			matchedSpecificSecret = true
			appendFinding("gitlab_token", "high", fingerprintSecretMatch(match), "Potential GitLab token detected.", lineNo)
		}
		for _, match := range npmTokenPattern.FindAllString(line, -1) {
			matchedSpecificSecret = true
			appendFinding("npm_token", "high", fingerprintSecretMatch(match), "Potential npm token detected.", lineNo)
		}
		for _, match := range slackTokenPattern.FindAllString(line, -1) {
			matchedSpecificSecret = true
			appendFinding("slack_token", "high", fingerprintSecretMatch(match), "Potential Slack token detected.", lineNo)
		}
		for _, match := range gcpAPIKeyPattern.FindAllString(line, -1) {
			matchedSpecificSecret = true
			appendFinding("gcp_api_key", "high", fingerprintSecretMatch(match), "Potential GCP API key detected.", lineNo, SecretReference{
				Kind: "cloud_identity", Provider: "gcp", Identifier: strings.TrimSpace(match),
			})
		}
		for _, match := range googleOAuthClientSecretPattern.FindAllString(line, -1) {
			matchedSpecificSecret = true
			appendFinding("google_oauth_client_secret", "high", fingerprintSecretMatch(match), "Potential Google OAuth client secret detected.", lineNo)
		}
		for _, match := range stripeAPIKeyPattern.FindAllString(line, -1) {
			matchedSpecificSecret = true
			appendFinding("stripe_api_key", "high", fingerprintSecretMatch(match), "Potential Stripe API key detected.", lineNo)
		}
		for _, match := range sendGridAPIKeyPattern.FindAllString(line, -1) {
			matchedSpecificSecret = true
			appendFinding("sendgrid_api_key", "high", fingerprintSecretMatch(match), "Potential SendGrid API key detected.", lineNo)
		}
		for _, match := range twilioAPIKeyPattern.FindAllString(line, -1) {
			matchedSpecificSecret = true
			appendFinding("twilio_api_key", "high", fingerprintSecretMatch(match), "Potential Twilio API key detected.", lineNo)
		}
		for _, match := range mailgunKeyPattern.FindAllString(line, -1) {
			matchedSpecificSecret = true
			appendFinding("mailgun_api_key", "high", fingerprintSecretMatch(match), "Potential Mailgun API key detected.", lineNo)
		}
		for _, match := range jwtTokenPattern.FindAllString(line, -1) {
			if !likelyJWTSecretLine(line) || !isLikelyJWT(match) {
				continue
			}
			matchedSpecificSecret = true
			appendFinding("jwt_token", "high", fingerprintSecretMatch(match), "Potential JWT bearer token detected.", lineNo)
		}
		if privateKeyPattern.MatchString(line) {
			matchedSpecificSecret = true
			appendFinding("private_key", "critical", "private_key", "Private key material detected.", lineNo)
		}
		if ref, ok := parseAzureStorageConnectionReference(line); ok {
			matchedSpecificSecret = true
			appendFinding(
				"azure_storage_connection_string",
				"critical",
				fingerprintSecretMatch(line),
				"Potential Azure storage connection string detected.",
				lineNo,
				ref,
			)
		}
		for _, match := range databaseURLPattern.FindAllString(line, -1) {
			if ref, ok := parseDatabaseConnectionReference(match); ok {
				matchedSpecificSecret = true
				appendFinding(
					"database_connection_string",
					"critical",
					fingerprintSecretMatch(match),
					"Potential database connection string detected.",
					lineNo,
					ref,
				)
				continue
			}
			if databaseConnectionLooksSecretLike(match) {
				matchedSpecificSecret = true
				appendFinding("database_connection_string", "critical", fingerprintSecretMatch(match), "Potential database connection string detected.", lineNo)
			}
		}
		if !matchedSpecificSecret {
			if value, key := inlineSecretValue(line); value != "" {
				appendFinding("inline_secret", "high", fingerprintSecretMatch(key+"="+value), "Inline secret-like assignment detected.", lineNo)
				matchedSpecificSecret = true
			}
		}
		if !matchedSpecificSecret {
			if token := entropySecretToken(line); token != "" {
				appendFinding("high_entropy_token", "medium", fingerprintSecretMatch(token), "High-entropy token detected in text content.", lineNo)
			}
		}
	}
	return findings
}

func dockerConfigSecretFindings(filePath string, data []byte) []SecretFinding {
	lowerPath := strings.ToLower(strings.TrimSpace(filePath))
	if path.Base(lowerPath) != "config.json" || !strings.Contains(lowerPath, "docker") {
		return nil
	}
	var cfg struct {
		Auths map[string]struct {
			Auth          string `json:"auth"`
			Username      string `json:"username"`
			Password      string `json:"password"`
			IdentityToken string `json:"identitytoken"`
			RegistryToken string `json:"registrytoken"`
		} `json:"auths"`
	}
	if err := json.Unmarshal(data, &cfg); err != nil || len(cfg.Auths) == 0 {
		return nil
	}
	findings := make([]SecretFinding, 0, len(cfg.Auths))
	for registry, auth := range cfg.Auths {
		host := normalizeRegistryHost(registry)
		if host == "" {
			continue
		}
		credential, fields, attrs := extractDockerRegistryCredential(auth)
		if credential == "" {
			continue
		}
		if len(fields) > 0 {
			attrs["credential_fields"] = strings.Join(fields, ",")
		}
		findings = append(findings, normalizeSecretFinding(SecretFinding{
			Type:        "docker_registry_credentials",
			Severity:    "high",
			Path:        filePath,
			Line:        1,
			Match:       fingerprintSecretMatch(credential),
			Description: "Potential Docker registry credentials detected.",
			References: []SecretReference{{
				Kind:       "registry",
				Provider:   providerFromRegistryHost(host),
				Identifier: host,
				Host:       host,
				Attributes: attrs,
			}},
		}))
	}
	return findings
}

func extractDockerRegistryCredential(auth struct {
	Auth          string `json:"auth"`
	Username      string `json:"username"`
	Password      string `json:"password"`
	IdentityToken string `json:"identitytoken"`
	RegistryToken string `json:"registrytoken"`
}) (string, []string, map[string]string) {
	attrs := map[string]string{"credential_format": "docker_config"}
	fields := make([]string, 0, 4)
	if token := strings.TrimSpace(auth.IdentityToken); token != "" {
		fields = append(fields, "identitytoken")
		return token, fields, attrs
	}
	if token := strings.TrimSpace(auth.RegistryToken); token != "" {
		fields = append(fields, "registrytoken")
		return token, fields, attrs
	}
	if password := strings.TrimSpace(auth.Password); password != "" {
		fields = append(fields, "password")
		if username := strings.TrimSpace(auth.Username); username != "" {
			attrs["username"] = username
			fields = append(fields, "username")
		}
		return password, fields, attrs
	}
	rawAuth := strings.TrimSpace(auth.Auth)
	if rawAuth == "" {
		return "", nil, nil
	}
	fields = append(fields, "auth")
	if decoded, err := base64.StdEncoding.DecodeString(rawAuth); err == nil {
		if user, pass, ok := strings.Cut(string(decoded), ":"); ok {
			if strings.TrimSpace(user) != "" {
				attrs["username"] = strings.TrimSpace(user)
				fields = append(fields, "username")
			}
			if strings.TrimSpace(pass) != "" {
				return strings.TrimSpace(pass), fields, attrs
			}
		}
	}
	return rawAuth, fields, attrs
}

func normalizeRegistryHost(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	raw = strings.TrimPrefix(raw, "https://")
	raw = strings.TrimPrefix(raw, "http://")
	raw = strings.TrimSuffix(raw, "/v1/")
	raw = strings.TrimSuffix(raw, "/v2/")
	raw = strings.TrimSuffix(raw, "/")
	if host, _, err := net.SplitHostPort(raw); err == nil {
		raw = host
	}
	return strings.ToLower(strings.TrimSpace(raw))
}

func providerFromRegistryHost(host string) string {
	switch {
	case strings.Contains(host, ".amazonaws.com"):
		return "aws"
	case strings.HasSuffix(host, ".gcr.io"), host == "gcr.io", strings.HasSuffix(host, ".pkg.dev"):
		return "gcp"
	case strings.HasSuffix(host, ".azurecr.io"):
		return "azure"
	case strings.Contains(host, "docker.io"):
		return "docker"
	default:
		return ""
	}
}

func likelyJWTSecretLine(line string) bool {
	lower := strings.ToLower(line)
	return inlineSecretPattern.MatchString(line) ||
		strings.Contains(lower, "bearer ") ||
		strings.Contains(lower, "authorization") ||
		strings.Contains(lower, "jwt") ||
		strings.Contains(lower, "token")
}

func normalizeSecretFinding(finding SecretFinding) SecretFinding {
	finding.Type = sanitizeSecretType(finding.Type)
	finding.Severity = strings.ToLower(strings.TrimSpace(finding.Severity))
	if finding.Severity == "" {
		finding.Severity = "high"
	}
	finding.Path = strings.TrimSpace(finding.Path)
	finding.Match = strings.TrimSpace(finding.Match)
	if finding.Match == "" {
		finding.Match = "<redacted>"
	}
	if strings.TrimSpace(finding.ID) == "" {
		finding.ID = findingID("secret", fmt.Sprintf("%s:%d:%s:%s", finding.Path, finding.Line, finding.Type, finding.Match))
	}
	return finding
}

func secretFindingKey(finding SecretFinding) string {
	refs := make([]string, 0, len(finding.References))
	for _, ref := range finding.References {
		refs = append(refs, strings.ToLower(strings.TrimSpace(strings.Join([]string{
			ref.Kind,
			ref.Provider,
			ref.Identifier,
			ref.Host,
			ref.Database,
		}, "|"))))
	}
	sort.Strings(refs)
	return strings.Join([]string{
		strings.TrimSpace(finding.Path),
		strconv.Itoa(finding.Line),
		strings.TrimSpace(finding.Match),
		strings.Join(refs, ","),
	}, "|")
}

func sanitizeSecretType(raw string) string {
	raw = strings.ToLower(strings.TrimSpace(raw))
	if raw == "" {
		return "secret"
	}
	var builder strings.Builder
	lastUnderscore := false
	for _, r := range raw {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			builder.WriteRune(r)
			lastUnderscore = false
			continue
		}
		if !lastUnderscore {
			builder.WriteByte('_')
			lastUnderscore = true
		}
	}
	return strings.Trim(builder.String(), "_")
}

func gcpServiceAccountKeyReference(data []byte) (SecretReference, bool) {
	var payload struct {
		Type         string `json:"type"`
		ClientEmail  string `json:"client_email"`
		PrivateKeyID string `json:"private_key_id"`
		TokenURI     string `json:"token_uri"`
	}
	if err := json.Unmarshal(data, &payload); err != nil {
		return SecretReference{}, false
	}
	if !strings.EqualFold(strings.TrimSpace(payload.Type), "service_account") {
		return SecretReference{}, false
	}
	email := strings.ToLower(strings.TrimSpace(payload.ClientEmail))
	if email == "" {
		return SecretReference{}, false
	}
	attributes := map[string]string{
		"credential_format": "json",
	}
	if strings.TrimSpace(payload.PrivateKeyID) != "" {
		attributes["private_key_id"] = strings.TrimSpace(payload.PrivateKeyID)
	}
	if strings.TrimSpace(payload.TokenURI) != "" {
		attributes["token_uri"] = strings.TrimSpace(payload.TokenURI)
	}
	return SecretReference{
		Kind:       "cloud_identity",
		Provider:   "gcp",
		Identifier: email,
		Attributes: attributes,
	}, true
}

func parseDatabaseConnectionReference(raw string) (SecretReference, bool) {
	raw = strings.TrimSpace(strings.Trim(raw, `"'`))
	if raw == "" {
		return SecretReference{}, false
	}
	if strings.HasPrefix(strings.ToLower(raw), "jdbc:sqlserver://") {
		return parseJDBCSQLServerReference(raw)
	}
	normalized := strings.TrimPrefix(raw, "jdbc:")
	parsed, err := url.Parse(normalized)
	if err != nil || parsed == nil {
		return SecretReference{}, false
	}
	if !databaseConnectionContainsSecret(parsed) {
		return SecretReference{}, false
	}
	host := strings.ToLower(strings.TrimSpace(parsed.Hostname()))
	if host == "" {
		return SecretReference{}, false
	}
	port, _ := strconv.Atoi(strings.TrimSpace(parsed.Port()))
	database := strings.Trim(strings.TrimSpace(parsed.Path), "/")
	if database == "" {
		if db := strings.TrimSpace(parsed.Query().Get("database")); db != "" {
			database = db
		}
		if db := strings.TrimSpace(parsed.Query().Get("databaseName")); db != "" {
			database = db
		}
	}
	scheme := strings.ToLower(strings.TrimSpace(parsed.Scheme))
	if scheme == "" {
		scheme = "unknown"
	}
	return SecretReference{
		Kind:       "database",
		Identifier: host,
		Host:       host,
		Port:       port,
		Database:   database,
		Attributes: map[string]string{"scheme": scheme},
	}, true
}

func parseJDBCSQLServerReference(raw string) (SecretReference, bool) {
	raw = strings.TrimPrefix(strings.TrimSpace(raw), "jdbc:sqlserver://")
	hostPort, _, _ := strings.Cut(raw, ";")
	hostPort = strings.TrimSpace(hostPort)
	if hostPort == "" {
		return SecretReference{}, false
	}
	host := hostPort
	port := 0
	if strings.Contains(hostPort, ":") {
		if parsedHost, parsedPort, err := net.SplitHostPort(hostPort); err == nil {
			host = parsedHost
			port, _ = strconv.Atoi(parsedPort)
		} else {
			host, _, _ = strings.Cut(hostPort, ":")
		}
	}
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return SecretReference{}, false
	}
	database := ""
	hasSecret := false
	for _, segment := range strings.Split(raw, ";") {
		key, value, ok := strings.Cut(segment, "=")
		if !ok {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(key)) {
		case "databasename", "database":
			database = strings.TrimSpace(value)
		case "password", "pwd", "access_token", "token", "secret":
			hasSecret = hasSecret || strings.TrimSpace(value) != ""
		}
	}
	if !hasSecret {
		return SecretReference{}, false
	}
	return SecretReference{
		Kind:       "database",
		Identifier: host,
		Host:       host,
		Port:       port,
		Database:   database,
		Attributes: map[string]string{"scheme": "sqlserver"},
	}, true
}

func parseAzureStorageConnectionReference(raw string) (SecretReference, bool) {
	values := parseDelimitedKeyValuePairs(raw, ";")
	if strings.TrimSpace(values["accountkey"]) == "" && strings.TrimSpace(values["sharedaccesssignature"]) == "" {
		return SecretReference{}, false
	}
	accountName := strings.TrimSpace(values["accountname"])
	if accountName == "" {
		return SecretReference{}, false
	}
	attributes := map[string]string{
		"credential_format": "connection_string",
	}
	if protocol := strings.TrimSpace(values["defaultendpointsprotocol"]); protocol != "" {
		attributes["protocol"] = protocol
	}
	if suffix := strings.TrimSpace(values["endpointsuffix"]); suffix != "" {
		attributes["endpoint_suffix"] = suffix
	}
	if strings.TrimSpace(values["sharedaccesssignature"]) != "" {
		attributes["auth_type"] = "sas"
	} else {
		attributes["auth_type"] = "account_key"
	}
	return SecretReference{
		Kind:       "cloud_identity",
		Provider:   "azure",
		Identifier: accountName,
		Attributes: attributes,
	}, true
}

func buildSBOM(generatedAt time.Time, components []SBOMComponent, dependencies []SBOMDependency) SBOMDocument {
	return SBOMDocument{
		Format:       "cyclonedx-json",
		SpecVersion:  "1.5",
		GeneratedAt:  generatedAt.UTC(),
		Components:   components,
		Dependencies: dependencies,
	}
}

func sbomComponentRef(pkg PackageRecord) string {
	return findingID("pkg", packageInventoryKey(pkg))
}

func sbomApplicationRef(ecosystem, name, location string) string {
	return findingID("app", strings.Join([]string{
		strings.TrimSpace(ecosystem),
		strings.TrimSpace(name),
		strings.TrimSpace(location),
	}, "|"))
}

func packageInventoryKey(pkg PackageRecord) string {
	return pkg.Ecosystem + "|" + pkg.Name + "|" + pkg.Version + "|" + pkg.Location
}

// MergePackageRecord applies the analyzer's canonical merge semantics for package inventory.
func MergePackageRecord(existing, incoming PackageRecord) PackageRecord {
	merged := existing
	merged.Manager = firstNonEmpty(existing.Manager, incoming.Manager)
	merged.PURL = firstNonEmpty(existing.PURL, incoming.PURL)
	merged.Location = firstNonEmpty(existing.Location, incoming.Location)
	merged.DirectDependency = existing.DirectDependency || incoming.DirectDependency
	merged.Reachable = existing.Reachable || incoming.Reachable
	merged.ImportFileCount = max(existing.ImportFileCount, incoming.ImportFileCount)
	switch {
	case merged.DependencyDepth == 0:
		merged.DependencyDepth = incoming.DependencyDepth
	case incoming.DependencyDepth > 0 && incoming.DependencyDepth < merged.DependencyDepth:
		merged.DependencyDepth = incoming.DependencyDepth
	}
	return merged
}

func dedupeFindings(findings []scanner.ContainerFinding) []scanner.ContainerFinding {
	if len(findings) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(findings))
	out := make([]scanner.ContainerFinding, 0, len(findings))
	for _, finding := range findings {
		id := strings.TrimSpace(finding.ID)
		if id == "" {
			id = finding.Type + "|" + finding.Title + "|" + finding.Package + "|" + finding.CVE
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, finding)
	}
	return out
}

func dedupeVulnerabilities(vulns []scanner.ImageVulnerability) []scanner.ImageVulnerability {
	if len(vulns) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(vulns))
	out := make([]scanner.ImageVulnerability, 0, len(vulns))
	for _, vuln := range vulns {
		identifier := strings.TrimSpace(vuln.CVE)
		if identifier == "" {
			identifier = firstNonEmpty(strings.TrimSpace(vuln.ID), strings.TrimSpace(vuln.Description))
		}
		key := identifier + "|" + strings.TrimSpace(vuln.Package) + "|" + strings.TrimSpace(vuln.InstalledVersion)
		if key == "||" {
			key = strings.TrimSpace(vuln.FixedVersion) + "|" + strings.TrimSpace(vuln.Severity)
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, vuln)
	}
	return out
}

func buildVulnerabilityFindings(vulns []scanner.ImageVulnerability) []scanner.ContainerFinding {
	if len(vulns) == 0 {
		return nil
	}
	findings := make([]scanner.ContainerFinding, 0, len(vulns))
	for _, vuln := range vulns {
		severity := strings.ToLower(strings.TrimSpace(vuln.Severity))
		if severity != "critical" && severity != "high" && !vuln.InKEV {
			continue
		}
		title := fmt.Sprintf("%s in %s", firstNonEmpty(vuln.CVE, vuln.ID, "unknown-vulnerability"), vuln.Package)
		if vuln.InKEV {
			title = "[KEV] " + title
			severity = "critical"
		}
		remediation := "No fix available. Consider using an alternative package or mitigating controls."
		if strings.TrimSpace(vuln.FixedVersion) != "" {
			remediation = fmt.Sprintf("Update %s to version %s", vuln.Package, vuln.FixedVersion)
		}
		findings = append(findings, scanner.ContainerFinding{
			ID:          findingID("pkg_vuln", firstNonEmpty(vuln.CVE, vuln.ID)+"|"+vuln.Package+"|"+vuln.InstalledVersion),
			Type:        "vulnerability",
			Severity:    severity,
			Title:       title,
			Description: vuln.Description,
			Remediation: remediation,
			CVE:         firstNonEmpty(vuln.CVE, vuln.ID),
			Package:     vuln.Package,
		})
	}
	return findings
}

func buildPURL(pkg PackageRecord) string {
	eco := strings.TrimSpace(pkg.Ecosystem)
	name := strings.TrimSpace(pkg.Name)
	version := strings.TrimSpace(pkg.Version)
	if eco == "" || name == "" || version == "" {
		return ""
	}
	return fmt.Sprintf("pkg:%s/%s@%s", eco, url.PathEscape(name), url.PathEscape(version))
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func findingID(prefix, value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	replacer := strings.NewReplacer("/", "_", "\\", "_", ":", "_", " ", "_", "@", "_", ".", "_", "=", "_", "|", "_")
	return prefix + ":" + replacer.Replace(value)
}

func fingerprintSecretMatch(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "<redacted>"
	}
	sum := sha256.Sum256([]byte(value))
	return fmt.Sprintf("sha256:%x", sum[:8])
}

func looksBinary(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	if bytes.IndexByte(data, 0) >= 0 {
		return true
	}
	return !utf8.Valid(data)
}

func entropySecretToken(line string) string {
	lowerLine := strings.ToLower(line)
	if !inlineSecretPattern.MatchString(line) && !strings.Contains(lowerLine, "bearer ") && !strings.Contains(lowerLine, "authorization:") {
		return ""
	}
	for _, token := range secretTokenPattern.FindAllString(line, -1) {
		if looksPlaceholderSecretValue(token) || looksSecretReferenceValue(token) {
			continue
		}
		if secretEntropy(token) >= 3.8 {
			return token
		}
	}
	return ""
}

func inlineSecretValue(line string) (string, string) {
	matches := inlineSecretAssignmentPattern.FindStringSubmatch(line)
	if len(matches) != 3 {
		return "", ""
	}
	key := strings.TrimSpace(matches[1])
	value := strings.TrimSpace(matches[2])
	value = strings.TrimRight(value, ",;")
	value = strings.TrimSpace(strings.Trim(value, `"'`))
	if key == "" || value == "" {
		return "", ""
	}
	if looksPlaceholderSecretValue(value) || looksSecretReferenceValue(value) {
		return "", ""
	}
	return value, key
}

func looksPlaceholderSecretValue(value string) bool {
	trimmed := strings.TrimSpace(strings.ToLower(value))
	switch trimmed {
	case "", "***", "******", "<redacted>", "changeme", "change-me", "replace-me", "replace_me", "example", "sample", "placeholder", "tbd", "todo", "null", "nil", "none":
		return true
	}
	return strings.HasPrefix(trimmed, "${") ||
		strings.HasPrefix(trimmed, "{{") ||
		strings.HasPrefix(trimmed, "<%") ||
		strings.HasPrefix(trimmed, "ref+") ||
		strings.HasPrefix(trimmed, "secret://") ||
		strings.HasPrefix(trimmed, "vault://") ||
		strings.HasPrefix(trimmed, "op://")
}

func looksSecretReferenceValue(value string) bool {
	trimmed := strings.TrimSpace(strings.ToLower(value))
	if trimmed == "" {
		return false
	}
	return strings.Contains(trimmed, "secretsmanager") ||
		strings.Contains(trimmed, "secretmanager.googleapis.com") ||
		strings.Contains(trimmed, "/secrets/") ||
		strings.Contains(trimmed, "vault:") ||
		strings.Contains(trimmed, "keyvault") ||
		strings.HasPrefix(trimmed, "projects/") ||
		strings.HasPrefix(trimmed, "arn:aws:secretsmanager:")
}

func databaseConnectionContainsSecret(parsed *url.URL) bool {
	if parsed == nil {
		return false
	}
	if parsed.User != nil {
		if password, ok := parsed.User.Password(); ok && strings.TrimSpace(password) != "" {
			return true
		}
	}
	query := parsed.Query()
	for key, values := range query {
		if !databaseQueryKeyLooksSensitive(key) {
			continue
		}
		for _, value := range values {
			if strings.TrimSpace(value) != "" {
				return true
			}
		}
	}
	return false
}

func databaseQueryKeyLooksSensitive(key string) bool {
	key = strings.TrimSpace(strings.ToLower(key))
	if key == "" {
		return false
	}
	key = strings.NewReplacer("-", "_", ".", "_").Replace(key)
	switch key {
	case "password", "passwd", "pwd", "token", "access_token", "secret", "api_key", "apikey", "client_secret", "private_key", "access_key":
		return true
	}
	return strings.Contains(key, "password") || strings.Contains(key, "token") || strings.Contains(key, "secret") || strings.Contains(key, "api_key")
}

func parseDelimitedKeyValuePairs(raw, separator string) map[string]string {
	parts := strings.Split(raw, separator)
	values := make(map[string]string, len(parts))
	for _, part := range parts {
		key, value, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(strings.ToLower(key))
		value = strings.TrimSpace(value)
		if key == "" || value == "" {
			continue
		}
		values[key] = value
	}
	return values
}

func databaseConnectionLooksSecretLike(raw string) bool {
	trimmed := strings.ToLower(strings.TrimSpace(raw))
	if trimmed == "" {
		return false
	}
	if strings.Contains(trimmed, "@") && strings.Contains(trimmed, "://") {
		return true
	}
	for _, token := range []string{
		";password=",
		";pwd=",
		";access_token=",
		";token=",
		";secret=",
		"?password=",
		"&password=",
		"?token=",
		"&token=",
		"?secret=",
		"&secret=",
		"?client_secret=",
		"&client_secret=",
	} {
		if strings.Contains(trimmed, token) {
			return true
		}
	}
	return false
}

func isLikelyJWT(token string) bool {
	parts := strings.Split(strings.TrimSpace(token), ".")
	if len(parts) != 3 {
		return false
	}
	header, ok := decodeJWTJSONSegment(parts[0])
	if !ok || strings.TrimSpace(fmt.Sprint(header["alg"])) == "" {
		return false
	}
	payload, ok := decodeJWTJSONSegment(parts[1])
	if !ok {
		return false
	}
	for _, key := range []string{"iss", "sub", "aud", "exp"} {
		if _, present := payload[key]; present {
			return true
		}
	}
	return false
}

func decodeJWTJSONSegment(segment string) (map[string]any, bool) {
	decoded, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(segment))
	if err != nil {
		return nil, false
	}
	var payload map[string]any
	if err := json.Unmarshal(decoded, &payload); err != nil {
		return nil, false
	}
	return payload, true
}

func secretEntropy(value string) float64 {
	if value == "" {
		return 0
	}
	freq := make(map[rune]float64)
	for _, ch := range value {
		freq[ch]++
	}
	length := float64(len(value))
	entropy := 0.0
	for _, count := range freq {
		p := count / length
		entropy -= p * math.Log2(p)
	}
	return entropy
}

func hasEnabledDirective(text, key string) bool {
	for _, line := range strings.Split(text, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		fields := strings.Fields(trimmed)
		if len(fields) < 2 || !strings.EqualFold(fields[0], key) {
			continue
		}
		value := strings.ToLower(strings.TrimSpace(fields[1]))
		return value == "yes" || value == "prohibit-password"
	}
	return false
}

func isLikelyEOL(osInfo OSInfo) bool {
	id := strings.ToLower(strings.TrimSpace(osInfo.ID))
	version := strings.TrimSpace(osInfo.VersionID)
	if version == "" {
		version = strings.TrimSpace(osInfo.Version)
	}
	switch id {
	case "ubuntu":
		return strings.HasPrefix(version, "18.04") || strings.HasPrefix(version, "20.04")
	case "debian":
		major := leadingNumericToken(version)
		return major != "" && (major == "9" || major == "10")
	case "alpine":
		return strings.HasPrefix(version, "3.16") || strings.HasPrefix(version, "3.17")
	case "amzn", "amazon", "amazonlinux":
		return version == "1"
	default:
		return false
	}
}

func leadingNumericToken(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	parts := strings.FieldsFunc(value, func(r rune) bool {
		return r == '.' || r == '-' || r == ' '
	})
	if len(parts) == 0 {
		return ""
	}
	if _, err := strconv.Atoi(parts[0]); err != nil {
		return ""
	}
	return parts[0]
}

func dedupeStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}
