package kandji

import (
	"context"
	"embed"

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
				Name:                  familyDevice,
				Path:                  "/devices",
				DetailPath:            "/devices/{device_id}/details",
				AllowBareDetailRecord: true,
				URNKind:               "kandji_device",
				IDKeys:                []string{"device_id", "general.device_id", "id", "serial_number", "hardware_overview.serial_number", "serial", "udid", "hardware_overview.udid"},
				TimestampKeys: []string{
					"updated_at", "last_check_in", "mdm.last_check_in", "kandji_agent.last_check_in", "last_check_in_at", "lastCheckIn", "created_at",
				},
				Attributes: map[string]string{
					"device_id":          "device_id|general.device_id|id",
					"device_uuid":        "udid|hardware_overview.udid|hardware_overview.uuid",
					"device_name":        "device_name|general.device_name",
					"hostname":           "device_name|general.device_name|network.local_hostname",
					"serial_number":      "serial_number|hardware_overview.serial_number|general.serial_number|hardware_overview.smbios_serial_number",
					"platform":           "platform|general.platform",
					"os":                 "platform|general.platform",
					"os_name":            "os_name|general.os_name",
					"os_version":         "os_version|general.os_version",
					"model":              "model|general.model|hardware_overview.model_name",
					"blueprint_id":       "blueprint_id|general.blueprint_uuid",
					"blueprint_name":     "blueprint_name|general.blueprint_name",
					"user_email":         "user.email|general.assigned_user.email",
					"owner_email":        "user.email|general.assigned_user.email",
					"resource_id":        "device_id|general.device_id|id",
					"resource_name":      "device_name|general.device_name",
					"user_id":            "user.id|general.assigned_user.id",
					"mdm_enabled":        "mdm_enabled|mdm.mdm_enabled",
					"filevault_enabled":  "filevault_enabled|filevault.filevault_enabled",
					"is_missing":         "is_missing",
					"agent_installed":    "agent_installed|kandji_agent.agent_installed|kandji_agent.is_agent_installed",
					"status":             "status|state|mdm_status",
					"last_check_in_at":   "last_check_in|mdm.last_check_in|kandji_agent.last_check_in|kandji_agent.last_check_in_datetime",
					"compliance_status":  "compliance_status|security.device_posture",
					"agent_installed_at": "agent_installed_at|kandji_agent.install_date",
				},
				StaticAttributes: map[string]string{"resource_type": "device", "source_product": "kandji"},
				Config:           jsonapi.FamilyConfig{ResourceURNKind: "kandji_device"},
			},
			{
				Name:    familyApplication,
				Path:    "/prism/apps",
				URNKind: "kandji_application",
				IDKeys: []string{
					"id",
					"app_id",
					"device_id+bundle_id",
					"device_id+path",
					"device_id+name",
				},
				TimestampKeys: []string{
					"updated_at", "installed_at", "last_seen_at", "last_collected_at", "created_at",
				},
				Attributes: map[string]string{
					"app_id":            "id|app_id|bundle_id",
					"device_id":         "device_id|device.id",
					"device_name":       "device_name|device.name|device__name",
					"hostname":          "hostname|device.name|device__name",
					"serial_number":     "serial_number",
					"application_name":  "name|bundle_name|executable",
					"app_name":          "name|bundle_name|executable",
					"package_name":      "name|bundle_name|executable",
					"bundle_id":         "bundle_id",
					"bundle_identifier": "bundle_id",
					"version":           "version|short_version",
					"installed_version": "version|short_version",
					"publisher":         "publisher|developer_name|obtained_from",
					"platform":          "platform|device__family",
					"ecosystem":         "ecosystem",
					"installed_at":      "installed_at|created_at",
					"path":              "path",
					"purl":              "purl",
					"owner_email":       "user.email|device__user_email",
					"resource_id":       "id|app_id|device_id+bundle_id|device_id+path|device_id+name",
					"resource_name":     "name|bundle_name|executable",
					"user_email":        "user.email|device__user_email",
				},
				StaticAttributes: map[string]string{"resource_type": "application", "source_product": "kandji"},
				Config:           jsonapi.FamilyConfig{ResourceURNKind: "kandji_application"},
			},
			{
				Name:    familyVulnerability,
				Path:    "/vulnerability-management/detections",
				URNKind: "kandji_vulnerability",
				IDKeys: []string{
					"id",
					"vulnerability_id",
					"device_id+cve_id+package_name+installed_version",
					"device_id+cve_id+application.name+installed_version",
					"device_id+cve_id+app.name+installed_version",
					"device_id+cve_id+name+installed_version",
					"device_id+cve_id+package_name+version",
					"device_id+cve_id+application.name+version",
					"device_id+cve_id+app.name+version",
					"device_id+cve_id+name+version",
					"device_id+cve_id",
				},
				TimestampKeys: []string{
					"updated_at", "detected_at", "first_detection_date", "last_observed_at", "latest_detection_date", "published_at",
				},
				Attributes: map[string]string{
					"vulnerability_id":  "id|vulnerability_id|cve_id",
					"cve_id":            "cve_id",
					"advisory_id":       "advisory_id",
					"ghsa_id":           "ghsa_id",
					"aliases":           "aliases",
					"severity":          "severity|cvss_severity",
					"title":             "title",
					"description":       "description|cve_description",
					"device_id":         "device_id|device.id",
					"device_name":       "device.name|device_name",
					"hostname":          "device.name|device_name|hostname",
					"serial_number":     "serial_number|device_serial_number",
					"application_name":  "application.name|app.name|package_name|name",
					"app_name":          "application.name|app.name|package_name|name",
					"package_name":      "package_name|application.name|app.name|name",
					"package":           "package_name|application.name|app.name|name",
					"version":           "installed_version|version",
					"installed_version": "installed_version|version",
					"fixed_version":     "fixed_version",
					"purl":              "purl",
					"ecosystem":         "ecosystem",
					"remediation":       "remediation",
					"remediation_state": "remediation_state",
					"patch_available":   "patch_available",
					"due_date":          "due_date",
					"resource_id":       "id|vulnerability_id|device_id+cve_id+package_name+installed_version|device_id+cve_id+application.name+installed_version|device_id+cve_id+app.name+installed_version|device_id+cve_id+name+installed_version|device_id+cve_id+package_name+version|device_id+cve_id+application.name+version|device_id+cve_id+app.name+version|device_id+cve_id+name+version|device_id+cve_id",
					"resource_name":     "cve_id|title",
					"detected_at":       "detected_at|first_detection_date",
					"last_observed_at":  "last_observed_at|latest_detection_date",
					"known_exploited":   "known_exploited",
				},
				StaticAttributes: map[string]string{"resource_type": "vulnerability", "source_product": "kandji"},
				Config:           jsonapi.FamilyConfig{ResourceURNKind: "kandji_vulnerability"},
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
	return sourcecdk.LoadSpecFromFS(catalogFS, "catalog.yaml")
}

func (s *Source) allowLoopbackForTest() {
	if s != nil && s.inner != nil {
		s.inner.AllowLoopbackBaseURL = true
	}
}
