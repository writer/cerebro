package filesystemanalyzer

import (
	"context"
	"time"

	"github.com/evalops/cerebro/internal/scanner"
)

type MalwareScanner interface {
	ScanData(ctx context.Context, data []byte, filename string) (*scanner.MalwareScanResult, error)
}

type Options struct {
	VulnerabilityScanner scanner.FilesystemScanner
	MalwareScanner       MalwareScanner
	Now                  func() time.Time
	MaxWalkEntries       int
	MaxFileBytes         int64
	MaxSecretFileBytes   int64
	MaxMalwareFileBytes  int64
}

type OSInfo struct {
	ID           string `json:"id,omitempty"`
	Name         string `json:"name,omitempty"`
	PrettyName   string `json:"pretty_name,omitempty"`
	Version      string `json:"version,omitempty"`
	VersionID    string `json:"version_id,omitempty"`
	Family       string `json:"family,omitempty"`
	Architecture string `json:"architecture,omitempty"`
	EOL          bool   `json:"eol,omitempty"`
}

type PackageRecord struct {
	Ecosystem string `json:"ecosystem"`
	Manager   string `json:"manager,omitempty"`
	Name      string `json:"name"`
	Version   string `json:"version"`
	PURL      string `json:"purl,omitempty"`
	Location  string `json:"location,omitempty"`
}

type SecretFinding struct {
	ID          string `json:"id"`
	Type        string `json:"type"`
	Severity    string `json:"severity"`
	Path        string `json:"path"`
	Line        int    `json:"line,omitempty"`
	Match       string `json:"match,omitempty"`
	Description string `json:"description,omitempty"`
}

type ConfigFinding struct {
	ID          string `json:"id"`
	Type        string `json:"type"`
	Severity    string `json:"severity"`
	Path        string `json:"path"`
	Title       string `json:"title"`
	Description string `json:"description,omitempty"`
	Remediation string `json:"remediation,omitempty"`
}

type MalwareFinding struct {
	ID          string `json:"id"`
	Path        string `json:"path"`
	Hash        string `json:"hash,omitempty"`
	MalwareType string `json:"malware_type,omitempty"`
	MalwareName string `json:"malware_name,omitempty"`
	Severity    string `json:"severity"`
	Confidence  int    `json:"confidence,omitempty"`
	Engine      string `json:"engine,omitempty"`
}

type SBOMComponent struct {
	BOMRef    string `json:"bom_ref"`
	Type      string `json:"type"`
	Name      string `json:"name"`
	Version   string `json:"version,omitempty"`
	PURL      string `json:"purl,omitempty"`
	Ecosystem string `json:"ecosystem,omitempty"`
	Location  string `json:"location,omitempty"`
}

type SBOMDocument struct {
	Format      string          `json:"format"`
	SpecVersion string          `json:"spec_version"`
	GeneratedAt time.Time       `json:"generated_at"`
	Components  []SBOMComponent `json:"components,omitempty"`
}

type Summary struct {
	PackageCount          int  `json:"package_count"`
	VulnerabilityCount    int  `json:"vulnerability_count"`
	SecretCount           int  `json:"secret_count"`
	MisconfigurationCount int  `json:"misconfiguration_count"`
	MalwareCount          int  `json:"malware_count"`
	Truncated             bool `json:"truncated,omitempty"`
}

type Report struct {
	Analyzer          string                       `json:"analyzer"`
	GeneratedAt       time.Time                    `json:"generated_at"`
	OS                OSInfo                       `json:"os,omitempty"`
	Packages          []PackageRecord              `json:"packages,omitempty"`
	Vulnerabilities   []scanner.ImageVulnerability `json:"vulnerabilities,omitempty"`
	Findings          []scanner.ContainerFinding   `json:"findings,omitempty"`
	Secrets           []SecretFinding              `json:"secrets,omitempty"`
	Misconfigurations []ConfigFinding              `json:"misconfigurations,omitempty"`
	Malware           []MalwareFinding             `json:"malware,omitempty"`
	SBOM              SBOMDocument                 `json:"sbom"`
	Summary           Summary                      `json:"summary"`
	Metadata          map[string]any               `json:"metadata,omitempty"`
}
