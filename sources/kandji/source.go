package kandji

import (
	"context"
	"embed"
	"fmt"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/sources/internal/jsonapi"
)

//go:embed catalog.yaml
var catalogFS embed.FS

const (
	sourceID       = "kandji"
	defaultFamily  = familyDevice
	defaultBaseURL = "https://api.kandji.io/api/v1"

	familyApplication   = "application"
	familyDevice        = "device"
	familyVulnerability = "vulnerability"
)

// Source is the Kandji/Iru Apple endpoint inventory source.
type Source struct {
	inner *jsonapi.Source
}

// New constructs the Kandji source.
func New() (*Source, error) {
	spec, err := loadSpec()
	if err != nil {
		return nil, err
	}
	inner, err := jsonapi.New(spec, jsonapi.Options{
		SourceID:        sourceID,
		DefaultBaseURL:  defaultBaseURL,
		DefaultFamily:   defaultFamily,
		RequireTenantID: true,
		TokenScheme:     "Bearer",
		Families: []jsonapi.Family{
			{
				Name:    familyDevice,
				Path:    "/devices",
				URNKind: "kandji_device",
				IDKeys:  []string{"device_id", "id", "serial_number", "serial", "udid"},
				TimestampKeys: []string{
					"updated_at", "last_check_in", "last_check_in_at", "lastCheckIn", "created_at",
				},
				Attributes: map[string]string{
					"device_id":          "device_id|id",
					"device_uuid":        "udid",
					"device_name":        "device_name",
					"hostname":           "device_name",
					"serial_number":      "serial_number",
					"platform":           "platform",
					"os":                 "platform",
					"os_name":            "os_name",
					"os_version":         "os_version",
					"model":              "model",
					"blueprint_id":       "blueprint_id",
					"blueprint_name":     "blueprint_name",
					"user_email":         "user.email",
					"owner_email":        "user.email",
					"user_id":            "user.id",
					"mdm_enabled":        "mdm_enabled",
					"filevault_enabled":  "filevault_enabled",
					"is_missing":         "is_missing",
					"agent_installed":    "agent_installed",
					"status":             "mdm_status|status|state",
					"last_check_in_at":   "last_check_in",
					"compliance_status":  "compliance_status",
					"agent_installed_at": "agent_installed_at",
				},
				StaticAttributes: map[string]string{"source_product": "kandji"},
			},
			{
				Name:    familyApplication,
				Path:    "/prism/apps",
				URNKind: "kandji_application",
				IDKeys:  []string{"id", "app_id"},
				TimestampKeys: []string{
					"updated_at", "installed_at", "last_seen_at",
				},
				Attributes: map[string]string{
					"app_id":            "id",
					"device_id":         "device_id|device.id",
					"device_name":       "device_name|device.name",
					"hostname":          "hostname|device.name",
					"serial_number":     "serial_number",
					"application_name":  "name",
					"app_name":          "name",
					"package_name":      "name",
					"bundle_id":         "bundle_id",
					"bundle_identifier": "bundle_id",
					"version":           "version",
					"installed_version": "version",
					"publisher":         "publisher",
					"platform":          "platform",
					"ecosystem":         "ecosystem",
					"installed_at":      "installed_at",
					"path":              "path",
					"purl":              "purl",
					"owner_email":       "user.email",
					"user_email":        "user.email",
				},
				StaticAttributes: map[string]string{"source_product": "kandji"},
			},
			{
				Name:    familyVulnerability,
				Path:    "/vulnerability-management/detections",
				URNKind: "kandji_vulnerability",
				IDKeys:  []string{"id", "vulnerability_id"},
				TimestampKeys: []string{
					"updated_at", "detected_at", "last_observed_at", "published_at",
				},
				Attributes: map[string]string{
					"vulnerability_id":  "id",
					"cve_id":            "cve_id",
					"advisory_id":       "advisory_id",
					"ghsa_id":           "ghsa_id",
					"aliases":           "aliases",
					"severity":          "severity",
					"title":             "title",
					"description":       "description",
					"device_id":         "device_id|device.id",
					"device_name":       "device.name|device_name",
					"hostname":          "device.name|device_name|hostname",
					"serial_number":     "serial_number",
					"application_name":  "application.name|app.name|package_name|name",
					"app_name":          "application.name|app.name|package_name|name",
					"package_name":      "package_name|application.name|app.name|name",
					"package":           "package_name|application.name|app.name|name",
					"version":           "installed_version",
					"installed_version": "installed_version",
					"fixed_version":     "fixed_version",
					"purl":              "purl",
					"ecosystem":         "ecosystem",
					"remediation":       "remediation",
					"remediation_state": "remediation_state",
					"patch_available":   "patch_available",
					"due_date":          "due_date",
					"last_observed_at":  "last_observed_at",
					"known_exploited":   "known_exploited",
				},
				StaticAttributes: map[string]string{"source_product": "kandji"},
			},
		},
	})
	if err != nil {
		return nil, err
	}
	return &Source{inner: inner}, nil
}

// Spec returns static Kandji source metadata.
func (s *Source) Spec() *cerebrov1.SourceSpec {
	if s == nil || s.inner == nil {
		return nil
	}
	return s.inner.Spec()
}

// Check validates the configured Kandji collection.
func (s *Source) Check(ctx context.Context, cfg sourcecdk.Config) error {
	return s.inner.Check(ctx, cfg)
}

// Discover returns Kandji URNs for the configured family.
func (s *Source) Discover(ctx context.Context, cfg sourcecdk.Config) ([]sourcecdk.URN, error) {
	return s.inner.Discover(ctx, cfg)
}

// Read pages Kandji records and emits kandji.* events.
func (s *Source) Read(ctx context.Context, cfg sourcecdk.Config, cursor *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
	return s.inner.Read(ctx, cfg, cursor)
}

func loadSpec() (*cerebrov1.SourceSpec, error) {
	specBytes, err := catalogFS.ReadFile("catalog.yaml")
	if err != nil {
		return nil, fmt.Errorf("read catalog: %w", err)
	}
	spec, err := sourcecdk.LoadCatalog(specBytes)
	if err != nil {
		return nil, fmt.Errorf("load catalog: %w", err)
	}
	return spec, nil
}

func (s *Source) allowLoopbackForTest() {
	if s != nil && s.inner != nil {
		s.inner.AllowLoopbackBaseURL = true
	}
}
