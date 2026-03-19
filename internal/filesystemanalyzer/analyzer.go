package filesystemanalyzer

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
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
	awsAccessKeyPattern = regexp.MustCompile(`AKIA[0-9A-Z]{16}`)
	githubTokenPattern  = regexp.MustCompile(`gh[pousr]_[A-Za-z0-9_]{20,}`)
	slackTokenPattern   = regexp.MustCompile(`xox[baprs]-[A-Za-z0-9-]{10,}`)
	privateKeyPattern   = regexp.MustCompile(`-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----`)
	inlineSecretPattern = regexp.MustCompile(`(?i)(password|passwd|pwd|secret|token|api[_-]?key|client[_-]?secret|connection[_-]?string)\s*[:=]`)
	secretTokenPattern  = regexp.MustCompile(`[A-Za-z0-9+/=_-]{20,}`)
	databaseURLPattern  = regexp.MustCompile(`(?i)(?:jdbc:sqlserver://[^\s'"]+|(?:jdbc:)?(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|sqlserver)://[^\s'"]+)`)
)

type Analyzer struct {
	vulnerabilityScanner scanner.FilesystemScanner
	vulnerabilityMatcher PackageVulnerabilityMatcher
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
	root, err := os.OpenRoot(absPath)
	if err != nil {
		return nil, fmt.Errorf("open filesystem root %s: %w", absPath, err)
	}
	defer func() { _ = root.Close() }()

	inv := newInventory(report.GeneratedAt)
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
				inv.addPackages(parsePackageRecords(filePath, data)...)
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
		if shouldParseConfigFile(filePath) {
			if data, ok, err := readLimitedFile(root, filePath, a.maxSecretFileBytes); err == nil && ok {
				inv.addConfigs(parseConfigFindings(filePath, data)...)
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
		if a.malwareScanner != nil && shouldMalwareScan(filePath, info.Mode(), info.Size()) {
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
	report.SBOM = buildSBOM(report.GeneratedAt, report.Packages)
	report.Findings = dedupeFindings(append(report.Findings, inv.findings...))
	report.Summary = Summary{
		PackageCount:          len(report.Packages),
		VulnerabilityCount:    len(report.Vulnerabilities),
		SecretCount:           len(report.Secrets),
		MisconfigurationCount: len(report.Misconfigurations),
		IaCArtifactCount:      len(report.IaCArtifacts),
		MalwareCount:          len(report.Malware),
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
	iacArtifactIDs map[string]struct{}
	secrets        []SecretFinding
	configs        []ConfigFinding
	iacArtifacts   []IaCArtifact
	malware        []MalwareFinding
	findings       []scanner.ContainerFinding
	entriesVisited int
	truncated      bool
	metadataErrors []string
}

func newInventory(now time.Time) *inventory {
	return &inventory{
		generatedAt:    now,
		packages:       make(map[string]PackageRecord),
		iacArtifactIDs: make(map[string]struct{}),
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
		key := pkg.Ecosystem + "|" + pkg.Name + "|" + pkg.Version + "|" + pkg.Location
		i.packages[key] = pkg
	}
}

func (i *inventory) addSecrets(findings ...SecretFinding) {
	for _, finding := range findings {
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
	case ".env", ".ini", ".cfg", ".conf", ".yaml", ".yml", ".json", ".xml", ".sh", ".bashrc", ".zshrc", ".py", ".js", ".ts", ".go", ".java", ".rb", ".php", ".txt":
		return true
	}
	base := path.Base(filePath)
	switch base {
	case ".env", "config", "authorized_keys", "known_hosts", ".bash_history", ".zsh_history", "credentials", "secrets", "Dockerfile":
		return true
	}
	return ext == ""
}

func shouldMalwareScan(filePath string, mode fs.FileMode, size int64) bool {
	if mode.IsDir() || mode&fs.ModeSymlink != 0 || size <= 0 || size > defaultMaxMalwareBytes {
		return false
	}
	if mode&0o111 != 0 {
		return true
	}
	ext := strings.ToLower(path.Ext(filePath))
	switch ext {
	case ".sh", ".py", ".js", ".jar", ".bin", ".exe":
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
		pkgs = append(pkgs, PackageRecord{Ecosystem: "golang", Manager: "go", Name: name, Version: version, Location: filePath})
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
	scanner := bufio.NewScanner(bytes.NewReader(data))
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		switch {
		case awsAccessKeyPattern.MatchString(line):
			match := awsAccessKeyPattern.FindString(line)
			appendFinding(
				"aws_access_key",
				"critical",
				fingerprintSecretMatch(match),
				"Potential AWS access key detected.",
				lineNo,
				SecretReference{Kind: "cloud_identity", Provider: "aws", Identifier: strings.TrimSpace(match)},
			)
		case githubTokenPattern.MatchString(line):
			appendFinding("github_token", "high", fingerprintSecretMatch(githubTokenPattern.FindString(line)), "Potential GitHub token detected.", lineNo)
		case slackTokenPattern.MatchString(line):
			appendFinding("slack_token", "high", fingerprintSecretMatch(slackTokenPattern.FindString(line)), "Potential Slack token detected.", lineNo)
		case privateKeyPattern.MatchString(line):
			appendFinding("private_key", "critical", "private_key", "Private key material detected.", lineNo)
		case databaseURLPattern.MatchString(line):
			match := databaseURLPattern.FindString(line)
			if ref, ok := parseDatabaseConnectionReference(match); ok {
				appendFinding(
					"database_connection_string",
					"critical",
					fingerprintSecretMatch(match),
					"Potential database connection string detected.",
					lineNo,
					ref,
				)
			} else {
				appendFinding("database_connection_string", "critical", fingerprintSecretMatch(match), "Potential database connection string detected.", lineNo)
			}
		case inlineSecretPattern.MatchString(line):
			appendFinding("inline_secret", "high", fingerprintSecretMatch(line), "Inline secret-like assignment detected.", lineNo)
		default:
			if token := entropySecretToken(line); token != "" {
				appendFinding("high_entropy_token", "medium", fingerprintSecretMatch(token), "High-entropy token detected in text content.", lineNo)
			}
		}
	}
	return findings
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
	for _, segment := range strings.Split(raw, ";") {
		key, value, ok := strings.Cut(segment, "=")
		if !ok {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(key)) {
		case "databasename", "database":
			database = strings.TrimSpace(value)
		}
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

func buildSBOM(generatedAt time.Time, packages []PackageRecord) SBOMDocument {
	components := make([]SBOMComponent, 0, len(packages))
	for _, pkg := range packages {
		components = append(components, SBOMComponent{
			BOMRef:    findingID("pkg", pkg.Ecosystem+":"+pkg.Name+":"+pkg.Version+":"+pkg.Location),
			Type:      "library",
			Name:      pkg.Name,
			Version:   pkg.Version,
			PURL:      pkg.PURL,
			Ecosystem: pkg.Ecosystem,
			Location:  pkg.Location,
		})
	}
	return SBOMDocument{
		Format:      "cyclonedx-json",
		SpecVersion: "1.5",
		GeneratedAt: generatedAt.UTC(),
		Components:  components,
	}
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
	seen := make(map[string]int, len(vulns))
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
		if idx, ok := seen[key]; ok {
			out[idx] = mergeImageVulnerability(out[idx], vuln)
			continue
		}
		seen[key] = len(out)
		out = append(out, vuln)
	}
	return out
}

func mergeImageVulnerability(existing, incoming scanner.ImageVulnerability) scanner.ImageVulnerability {
	merged := existing
	if strings.TrimSpace(merged.ID) == "" {
		merged.ID = strings.TrimSpace(incoming.ID)
	}
	if strings.TrimSpace(merged.CVE) == "" {
		merged.CVE = strings.TrimSpace(incoming.CVE)
	}
	if strings.TrimSpace(merged.Severity) == "" || strings.EqualFold(strings.TrimSpace(merged.Severity), "unknown") {
		merged.Severity = strings.TrimSpace(incoming.Severity)
	}
	if strings.TrimSpace(merged.FixedVersion) == "" {
		merged.FixedVersion = strings.TrimSpace(incoming.FixedVersion)
	}
	if strings.TrimSpace(merged.Description) == "" {
		merged.Description = strings.TrimSpace(incoming.Description)
	}
	if merged.CVSS == 0 {
		merged.CVSS = incoming.CVSS
	}
	if merged.Published.IsZero() {
		merged.Published = incoming.Published
	}
	merged.Exploitable = merged.Exploitable || incoming.Exploitable
	merged.InKEV = merged.InKEV || incoming.InKEV
	merged.References = dedupeStrings(append(append([]string{}, merged.References...), incoming.References...))
	return merged
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
	if !strings.Contains(line, "=") && !strings.Contains(line, ":") {
		return ""
	}
	for _, token := range secretTokenPattern.FindAllString(line, -1) {
		if secretEntropy(token) >= 3.8 {
			return token
		}
	}
	return ""
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
