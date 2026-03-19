package vulndb

import "time"

// Vulnerability represents a normalized advisory record persisted in the advisory store.
type Vulnerability struct {
	ID             string     `json:"id"`
	Aliases        []string   `json:"aliases,omitempty"`
	Summary        string     `json:"summary,omitempty"`
	Details        string     `json:"details,omitempty"`
	Severity       string     `json:"severity,omitempty"`
	CVSS           float64    `json:"cvss,omitempty"`
	PublishedAt    time.Time  `json:"published_at,omitempty"`
	ModifiedAt     time.Time  `json:"modified_at,omitempty"`
	WithdrawnAt    *time.Time `json:"withdrawn_at,omitempty"`
	Source         string     `json:"source,omitempty"`
	References     []string   `json:"references,omitempty"`
	EPSSScore      float64    `json:"epss_score,omitempty"`
	EPSSPercentile float64    `json:"epss_percentile,omitempty"`
	InKEV          bool       `json:"in_kev,omitempty"`
}

// AffectedPackage captures one affected package/range tuple for a vulnerability.
type AffectedPackage struct {
	VulnerabilityID     string `json:"vulnerability_id"`
	Ecosystem           string `json:"ecosystem"`
	PackageName         string `json:"package_name"`
	RangeType           string `json:"range_type,omitempty"`
	Introduced          string `json:"introduced,omitempty"`
	Fixed               string `json:"fixed,omitempty"`
	LastAffected        string `json:"last_affected,omitempty"`
	VulnerableVersion   string `json:"vulnerable_version,omitempty"`
	Distribution        string `json:"distribution,omitempty"`
	DistributionVersion string `json:"distribution_version,omitempty"`
}

// SyncState tracks importer progress for a particular source.
type SyncState struct {
	Source        string            `json:"source"`
	ETag          string            `json:"etag,omitempty"`
	Cursor        string            `json:"cursor,omitempty"`
	LastAttemptAt time.Time         `json:"last_attempt_at,omitempty"`
	LastSuccessAt time.Time         `json:"last_success_at,omitempty"`
	RecordsSynced int               `json:"records_synced,omitempty"`
	Metadata      map[string]string `json:"metadata,omitempty"`
}

// Stats summarizes persisted advisory inventory.
type Stats struct {
	VulnerabilityCount int       `json:"vulnerability_count"`
	PackageRangeCount  int       `json:"package_range_count"`
	KEVCount           int       `json:"kev_count"`
	LastUpdatedAt      time.Time `json:"last_updated_at,omitempty"`
}

// Match represents one vulnerability matched against an installed package.
type Match struct {
	Vulnerability    Vulnerability `json:"vulnerability"`
	InstalledVersion string        `json:"installed_version"`
	PackageName      string        `json:"package_name"`
	FixedVersion     string        `json:"fixed_version,omitempty"`
}
