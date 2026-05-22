package vulndb

import (
	"strings"
	"time"
)

// Vulnerability is a normalized advisory record keyed by a stable vulnerability ID.
type Vulnerability struct {
	ID          string
	Aliases     []string
	Summary     string
	Details     string
	Severity    string
	CVSSScore   float64
	CVSSVector  string
	PublishedAt time.Time
	ModifiedAt  time.Time
	WithdrawnAt time.Time
	Source      string
	References  []Reference
	EPSS        *EPSS
	KEV         *KEV
}

// Reference points to upstream advisory or vendor context.
type Reference struct {
	URL  string
	Type string
}

// EPSS stores Exploit Prediction Scoring System enrichment.
type EPSS struct {
	Score      float64
	Percentile float64
	UpdatedAt  time.Time
}

// KEV stores CISA Known Exploited Vulnerability enrichment.
type KEV struct {
	Listed                     bool
	KnownRansomwareCampaignUse string
	RequiredAction             string
	DueDate                    time.Time
	UpdatedAt                  time.Time
	Notes                      string
}

// AffectedPackage describes one package/version range affected by a vulnerability.
type AffectedPackage struct {
	VulnerabilityID     string
	Source              string
	Ecosystem           string
	PackageName         string
	RangeType           string
	Introduced          string
	IntroducedExclusive string
	Fixed               string
	LastAffected        string
	VulnerableVersion   string
	DistroName          string
	DistroVersion       string
}

// PackageQuery identifies an installed package to match against advisories.
type PackageQuery struct {
	Ecosystem string
	Name      string
	Version   string
}

// Match ties an installed package to a matching advisory and affected range.
type Match struct {
	Vulnerability   Vulnerability
	AffectedPackage AffectedPackage
}

// SyncState tracks durable per-source feed synchronization progress.
type SyncState struct {
	Source        string
	Cursor        string
	ETag          string
	LastSyncedAt  time.Time
	LastSuccessAt time.Time
	LastError     string
}

// SyncJob tracks durable advisory feed synchronization work.
type SyncJob struct {
	ID                string
	Source            string
	FeedURL           string
	AllowInsecureHTTP bool
	Interval          time.Duration
	NextRunAt         time.Time
	LeaseOwner        string
	LeaseExpiresAt    time.Time
	LastStartedAt     time.Time
	LastFinishedAt    time.Time
	LastSuccessAt     time.Time
	LastError         string
	Runs              int64
}

// Stats summarizes persisted advisory data.
type Stats struct {
	Vulnerabilities  int
	AffectedPackages int
	SyncSources      int
	SyncJobs         int
}

// NormalizeIdentifier canonicalizes vulnerability identifiers and aliases.
func NormalizeIdentifier(value string) string {
	return strings.ToUpper(strings.TrimSpace(value))
}

func normalizeEcosystem(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func normalizePackageName(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

// PackageLookupNames returns package-name keys that should be considered for a query.
func PackageLookupNames(ecosystem string, packageName string) []string {
	name := normalizePackageName(packageName)
	if name == "" {
		return nil
	}
	names := []string{name}
	if strings.HasPrefix(normalizeEcosystem(ecosystem), "cpe:") {
		names = append(names, cpePackageLookupPrefixes(name)...)
	}
	return dedupeStrings(names)
}

func cpePackageLookupPrefixes(name string) []string {
	parts := strings.Split(name, ":")
	firstQualifier := len(parts)
	for i, part := range parts {
		if strings.Contains(part, "=") {
			firstQualifier = i
			break
		}
	}
	if firstQualifier == len(parts) {
		return nil
	}
	base := parts[:firstQualifier]
	qualifiers := parts[firstQualifier:]
	prefixes := make([]string, 0, 1<<len(qualifiers))
	for size := len(qualifiers) - 1; size >= 0; size-- {
		cpeQualifierCombinations(qualifiers, size, func(selected []string) {
			candidate := append(append([]string{}, base...), selected...)
			prefix := strings.Join(candidate, ":")
			if prefix != "" {
				prefixes = append(prefixes, prefix)
			}
		})
	}
	return prefixes
}

func cpeQualifierCombinations(qualifiers []string, size int, visit func([]string)) {
	if size == 0 {
		visit(nil)
		return
	}
	var walk func(start int, selected []string)
	walk = func(start int, selected []string) {
		if len(selected) == size {
			visit(selected)
			return
		}
		remaining := size - len(selected)
		for i := start; i <= len(qualifiers)-remaining; i++ {
			walk(i+1, append(selected, qualifiers[i]))
		}
	}
	walk(0, nil)
}

func dedupeStrings(values []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func packageKey(ecosystem string, packageName string) string {
	return normalizeEcosystem(ecosystem) + "\x00" + normalizePackageName(packageName)
}

func cloneVulnerability(v Vulnerability) Vulnerability {
	v.ID = NormalizeIdentifier(v.ID)
	v.Aliases = cloneStrings(v.Aliases)
	for i, alias := range v.Aliases {
		v.Aliases[i] = NormalizeIdentifier(alias)
	}
	v.References = append([]Reference(nil), v.References...)
	if v.EPSS != nil {
		epss := *v.EPSS
		v.EPSS = &epss
	}
	if v.KEV != nil {
		kev := *v.KEV
		v.KEV = &kev
	}
	return v
}

func cloneStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	return append([]string(nil), values...)
}

func normalizeSyncJob(job SyncJob) SyncJob {
	job.ID = strings.TrimSpace(job.ID)
	job.Source = normalizeSource(job.Source)
	job.FeedURL = strings.TrimSpace(job.FeedURL)
	job.LeaseOwner = strings.TrimSpace(job.LeaseOwner)
	job.LastError = strings.TrimSpace(job.LastError)
	return job
}

func normalizeSource(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}
