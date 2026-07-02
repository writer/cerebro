package kolide

import (
	"embed"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/sourcecdk"
)

//go:embed catalog.yaml
var catalogFS embed.FS

const (
	sourceID          = "kolide"
	defaultBaseURL    = "https://api.kolide.com"
	defaultAPIVersion = "2026-04-07"
	defaultFamily     = familyDevice

	familyCheck         = "check"
	familyDevice        = "device"
	familyIssue         = "issue"
	familySoftware      = "software"
	familyUserDevice    = "user_device"
	familyVulnerability = "vulnerability"
)

func loadSpec() (*cerebrov1.SourceSpec, error) {
	return sourcecdk.LoadSpecFromFS(catalogFS, "catalog.yaml")
}
