package vulndb

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/filesystemanalyzer"
	"github.com/writer/cerebro/internal/scanner"
	"golang.org/x/mod/semver"
)

type advisoryStore interface {
	UpsertAdvisory(ctx context.Context, vuln Vulnerability, affected []AffectedPackage) error
	LookupVulnerability(ctx context.Context, idOrAlias string) (*Vulnerability, error)
	ListPackageCandidates(ctx context.Context, ecosystem, packageName string) ([]candidateRecord, error)
	UpdateSyncState(ctx context.Context, state SyncState) error
	ListSyncStates(ctx context.Context) ([]SyncState, error)
	Stats(ctx context.Context) (Stats, error)
	MarkKEV(ctx context.Context, cves []string) (int64, error)
	UpsertEPSS(ctx context.Context, cve string, score, percentile float64) (int64, error)
}

type Service struct {
	store advisoryStore
	now   func() time.Time
}

func NewService(store advisoryStore) *Service {
	return &Service{store: store, now: time.Now}
}

func (s *Service) LookupCVE(cve string) (*scanner.CVEInfo, bool) {
	if s == nil || s.store == nil {
		return nil, false
	}
	vuln, err := s.store.LookupVulnerability(context.Background(), cve)
	if err != nil || vuln == nil {
		return nil, false
	}
	return &scanner.CVEInfo{
		ID:          vuln.ID,
		Severity:    vuln.Severity,
		CVSS:        vuln.CVSS,
		Published:   vuln.PublishedAt,
		Exploitable: vuln.InKEV || vuln.EPSSScore >= 0.5,
		InKEV:       vuln.InKEV,
	}, true
}

func (s *Service) IsKEV(cve string) bool {
	info, ok := s.LookupCVE(cve)
	return ok && info.InKEV
}

func (s *Service) Stats(ctx context.Context) (Stats, error) {
	if s == nil || s.store == nil {
		return Stats{}, nil
	}
	return s.store.Stats(ctx)
}

func (s *Service) ListSyncStates(ctx context.Context) ([]SyncState, error) {
	if s == nil || s.store == nil {
		return nil, nil
	}
	return s.store.ListSyncStates(ctx)
}

func (s *Service) MatchPackages(ctx context.Context, _ filesystemanalyzer.OSInfo, packages []filesystemanalyzer.PackageRecord) ([]scanner.ImageVulnerability, error) {
	if s == nil || s.store == nil || len(packages) == 0 {
		return nil, nil
	}
	matches := make([]scanner.ImageVulnerability, 0)
	seen := make(map[string]struct{})
	for _, pkg := range packages {
		ecosystem := normalizeEcosystem(pkg.Ecosystem)
		name := strings.TrimSpace(strings.ToLower(pkg.Name))
		if ecosystem == "" || name == "" || strings.TrimSpace(pkg.Version) == "" {
			continue
		}
		candidates, err := s.store.ListPackageCandidates(ctx, ecosystem, name)
		if err != nil {
			return nil, err
		}
		for _, candidate := range candidates {
			if candidate.Vulnerability.WithdrawnAt != nil {
				continue
			}
			matched, fixedVersion := matchPackageVersion(pkg.Version, candidate.Affected)
			if !matched {
				continue
			}
			identifier := primaryVulnerabilityID(candidate.Vulnerability)
			key := strings.ToLower(identifier + "|" + name + "|" + pkg.Version)
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			matches = append(matches, scanner.ImageVulnerability{
				ID:               fmt.Sprintf("vulndb:%s:%s", sanitizeID(identifier), sanitizeID(name)),
				CVE:              identifier,
				Severity:         normalizeSeverity(candidate.Vulnerability.Severity),
				Package:          pkg.Name,
				InstalledVersion: pkg.Version,
				FixedVersion:     fixedVersion,
				Description:      firstNonEmpty(candidate.Vulnerability.Summary, candidate.Vulnerability.Details),
				CVSS:             candidate.Vulnerability.CVSS,
				Published:        candidate.Vulnerability.PublishedAt,
				Exploitable:      candidate.Vulnerability.InKEV || candidate.Vulnerability.EPSSScore >= 0.5,
				InKEV:            candidate.Vulnerability.InKEV,
				References:       uniqueStrings(candidate.Vulnerability.References),
			})
		}
	}
	return matches, nil
}

func matchPackageVersion(installed string, affected AffectedPackage) (bool, string) {
	installed = strings.TrimSpace(installed)
	if installed == "" {
		return false, ""
	}
	if affected.VulnerableVersion != "" {
		return installed == strings.TrimSpace(affected.VulnerableVersion), affected.Fixed
	}
	rangeType := strings.TrimSpace(strings.ToUpper(affected.RangeType))
	if rangeType != "" && rangeType != "SEMVER" && rangeType != "ECOSYSTEM" {
		return false, ""
	}
	if affected.Introduced != "" {
		cmp, ok := comparePackageVersions(affected.Ecosystem, installed, affected.Introduced)
		if !ok {
			return false, ""
		}
		if cmp < 0 {
			return false, ""
		}
	}
	if affected.Fixed != "" {
		cmp, ok := comparePackageVersions(affected.Ecosystem, installed, affected.Fixed)
		if !ok {
			return false, ""
		}
		if cmp >= 0 {
			return false, ""
		}
	}
	if affected.LastAffected != "" {
		cmp, ok := comparePackageVersions(affected.Ecosystem, installed, affected.LastAffected)
		if !ok {
			return false, ""
		}
		if cmp > 0 {
			return false, ""
		}
	}
	return true, affected.Fixed
}

func comparePackageVersions(ecosystem, left, right string) (int, bool) {
	switch normalizeEcosystem(ecosystem) {
	case "apk":
		return compareAPKVersions(left, right)
	default:
		return compareSemverLooseVersions(left, right)
	}
}

func compareSemverLooseVersions(left, right string) (int, bool) {
	leftVersion, ok := parseSemverLoose(left)
	if !ok {
		return 0, false
	}
	rightVersion, ok := parseSemverLoose(right)
	if !ok {
		return 0, false
	}
	return semver.Compare(leftVersion, rightVersion), true
}

func compareAPKVersions(left, right string) (int, bool) {
	leftBase, leftRevision, ok := splitAPKRevision(left)
	if !ok {
		return 0, false
	}
	rightBase, rightRevision, ok := splitAPKRevision(right)
	if !ok {
		return 0, false
	}
	cmp, ok := compareSemverLooseVersions(leftBase, rightBase)
	if !ok {
		return 0, false
	}
	if cmp != 0 {
		return cmp, true
	}
	switch {
	case leftRevision < rightRevision:
		return -1, true
	case leftRevision > rightRevision:
		return 1, true
	default:
		return 0, true
	}
}

func splitAPKRevision(value string) (string, int, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", 0, false
	}
	idx := strings.LastIndex(value, "-r")
	if idx < 0 {
		return value, 0, true
	}
	revision, err := strconv.Atoi(value[idx+2:])
	if err != nil {
		return "", 0, false
	}
	return value[:idx], revision, true
}

func parseSemverLoose(value string) (string, bool) {
	value = strings.TrimSpace(value)
	value = strings.TrimPrefix(value, "=")
	if value == "" {
		return "", false
	}
	if !strings.HasPrefix(value, "v") {
		value = "v" + value
	}
	core := value
	suffix := ""
	if idx := strings.IndexAny(value, "-+"); idx >= 0 {
		core = value[:idx]
		suffix = value[idx:]
	}
	parts := strings.Split(strings.TrimPrefix(core, "v"), ".")
	if len(parts) == 2 {
		core = "v" + parts[0] + "." + parts[1] + ".0"
	} else if len(parts) == 1 {
		core = "v" + parts[0] + ".0.0"
	}
	value = core + suffix
	if !semver.IsValid(value) {
		return "", false
	}
	return value, true
}

func primaryVulnerabilityID(v Vulnerability) string {
	if strings.HasPrefix(strings.ToUpper(v.ID), "CVE-") {
		return strings.ToUpper(v.ID)
	}
	for _, alias := range v.Aliases {
		if strings.HasPrefix(strings.ToUpper(alias), "CVE-") {
			return strings.ToUpper(alias)
		}
	}
	if strings.TrimSpace(v.ID) != "" {
		return strings.ToUpper(v.ID)
	}
	for _, alias := range v.Aliases {
		if strings.TrimSpace(alias) != "" {
			return strings.ToUpper(alias)
		}
	}
	return "UNKNOWN"
}

func normalizeSeverity(value string) string {
	value = strings.TrimSpace(strings.ToLower(value))
	switch value {
	case "critical":
		return "critical"
	case "high":
		return "high"
	case "medium", "moderate":
		return "medium"
	case "low":
		return "low"
	case "negligible", "info", "informational":
		return "low"
	case "":
		return "unknown"
	default:
		return value
	}
}

func severityFromScore(score float64) string {
	switch {
	case score >= 9.0:
		return "critical"
	case score >= 7.0:
		return "high"
	case score >= 4.0:
		return "medium"
	case score > 0:
		return "low"
	default:
		return "unknown"
	}
}

func normalizeEcosystem(value string) string {
	value = strings.TrimSpace(strings.ToLower(value))
	switch value {
	case "go", "golang":
		return "golang"
	case "pip", "python", "pypi":
		return "pypi"
	case "npm":
		return "npm"
	case "cargo", "rust":
		return "cargo"
	case "packagist", "composer":
		return "composer"
	case "maven":
		return "maven"
	case "nuget":
		return "nuget"
	case "apk":
		return "apk"
	case "alpine":
		return "apk"
	case "deb", "debian":
		return "deb"
	default:
		return value
	}
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		result = append(result, trimmed)
	}
	return result
}

func uniqueUpperStrings(values []string) []string {
	upper := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(strings.ToUpper(value))
		if trimmed != "" {
			upper = append(upper, trimmed)
		}
	}
	return uniqueStrings(upper)
}

func sanitizeID(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.ReplaceAll(value, ":", "-")
	value = strings.ReplaceAll(value, "/", "-")
	value = strings.ReplaceAll(value, "@", "-")
	value = strings.ReplaceAll(value, " ", "-")
	return value
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
