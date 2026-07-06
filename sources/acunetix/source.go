package acunetix

import (
	"context"
	"embed"
	"fmt"
	"strings"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/sources/internal/jsonapi"
)

//go:embed catalog.yaml
var catalogFS embed.FS

const (
	sourceID               = "acunetix"
	defaultFamily          = familyTargets
	defaultHealthPath      = "/targets"
	defaultBaseURLTemplate = "${config.base_url}"
	tokenHeader            = "X-Auth"
	tokenScheme            = ""
	familyTargets          = "targets"
	familyScans            = "scans"
	familyVulnerabilities  = "vulnerabilities"
	familyScanningProfiles = "scanning_profiles"
	familyReports          = "reports"
)

var templateKeys = []string{"base_url", "token"}

type Source struct {
	inner         *jsonapi.Source
	allowLoopback bool
}

func New() (*Source, error) {
	spec, err := loadSpec()
	if err != nil {
		return nil, err
	}
	inner, err := jsonapi.New(spec, jsonapi.Options{
		SourceID:        sourceID,
		DefaultFamily:   defaultFamily,
		RequireTenantID: true,
		AuthModel:       "api_key",
		TokenHeader:     tokenHeader,
		TokenScheme:     tokenScheme,
		Families: []jsonapi.Family{
			{
				Name:             familyTargets,
				Path:             "/targets",
				URNKind:          "acunetix_targets",
				IDKeys:           []string{"target_id", "id", "address", "resource_urn"},
				CursorParam:      "c",
				NextCursorKeys:   []string{"pagination.next_cursor", "pagination.cursor", "pagination.next"},
				PageSizeParams:   []string{"l"},
				ListKeys:         []string{"targets"},
				TimestampKeys:    []string{"last_scan_date", "updated_at", "created_at"},
				Attributes:       map[string]string{"criticality": "criticality", "description": "description", "evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "id": "target_id|id|address", "name": "address|description|target_id", "observed_at": "last_scan_date|updated_at|created_at", "resource_id": "target_id|id|address", "resource_name": "address|description|target_id", "resource_type": "type|target", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "event_id|target_id|id|metadata.event_id", "target_id": "target_id|id", "tenant_id": "tenant_id|metadata.tenant_id"},
				StaticAttributes: map[string]string{"record_class": "asset", "resource_type": "target", "schema": "targets", "source_system": "acunetix"},
			},
			{
				Name:             familyScans,
				Path:             "/scans",
				URNKind:          "acunetix_scans",
				IDKeys:           []string{"scan_id", "id", "target_id", "resource_urn"},
				CursorParam:      "c",
				NextCursorKeys:   []string{"pagination.next_cursor", "pagination.cursor", "pagination.next"},
				PageSizeParams:   []string{"l"},
				ListKeys:         []string{"scans"},
				TimestampKeys:    []string{"start_date", "current_session.start_date", "updated_at", "created_at"},
				Attributes:       map[string]string{"description": "profile_name|target.description|summary", "evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "finding_id": "scan_id|id", "observed_at": "start_date|current_session.start_date|updated_at|created_at", "profile_id": "profile_id", "resource_id": "target_id|target.target_id", "resource_name": "target.address|target.description|address|name", "resource_type": "target", "resource_urn": "resource_urn|urn|metadata.resource_urn", "scan_id": "scan_id|id", "severity": "threat|severity", "source_event_id": "event_id|scan_id|id|metadata.event_id", "status": "current_session.status|status", "tenant_id": "tenant_id|metadata.tenant_id", "title": "profile_name|scan_id|id"},
				StaticAttributes: map[string]string{"record_class": "finding", "resource_type": "target", "schema": "scans", "source_system": "acunetix"},
			},
			{
				Name:             familyVulnerabilities,
				Path:             "/vulnerabilities",
				URNKind:          "acunetix_vulnerabilities",
				IDKeys:           []string{"vuln_id", "vulnerability_id", "id", "resource_urn"},
				CursorParam:      "c",
				NextCursorKeys:   []string{"pagination.next_cursor", "pagination.cursor", "pagination.next"},
				PageSizeParams:   []string{"l"},
				ListKeys:         []string{"vulnerabilities"},
				TimestampKeys:    []string{"last_seen", "updated_at", "created_at"},
				Attributes:       map[string]string{"affects_url": "affects_url", "description": "description|long_description|vt_name|summary", "evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "finding_id": "vuln_id|vulnerability_id|id", "observed_at": "last_seen|updated_at|created_at", "resource_id": "target_id|target.target_id|resource_id", "resource_name": "affects_url|target.address|resource_name|name", "resource_type": "target", "resource_urn": "resource_urn|urn|metadata.resource_urn", "severity": "severity", "source_event_id": "event_id|vuln_id|vulnerability_id|id|metadata.event_id", "status": "status", "tenant_id": "tenant_id|metadata.tenant_id", "title": "vt_name|name|title|vuln_id"},
				StaticAttributes: map[string]string{"record_class": "finding", "resource_type": "target", "schema": "vulnerabilities", "source_system": "acunetix"},
			},
			{
				Name:             familyScanningProfiles,
				Path:             "/scanning_profiles",
				URNKind:          "acunetix_scanning_profiles",
				IDKeys:           []string{"profile_id", "scanning_profile_id", "id", "name"},
				CursorParam:      "c",
				NextCursorKeys:   []string{"pagination.next_cursor", "pagination.cursor", "pagination.next"},
				PageSizeParams:   []string{"l"},
				ListKeys:         []string{"scanning_profiles"},
				TimestampKeys:    []string{"updated_at", "created_at"},
				Attributes:       map[string]string{"evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "observed_at": "updated_at|created_at", "policy_created_at": "created_at", "policy_description": "description|name", "policy_id": "profile_id|scanning_profile_id|id", "policy_name": "name", "policy_severity": "sort_order|severity", "policy_status": "status|enabled", "policy_type": "scanning_profile", "resource_id": "profile_id|scanning_profile_id|id", "resource_name": "name", "resource_type": "scanning_profile", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "event_id|profile_id|scanning_profile_id|id|metadata.event_id", "tenant_id": "tenant_id|metadata.tenant_id"},
				StaticAttributes: map[string]string{"record_class": "policy", "resource_type": "scanning_profile", "schema": "scanning_profiles", "source_system": "acunetix"},
			},
			{
				Name:             familyReports,
				Path:             "/reports",
				URNKind:          "acunetix_reports",
				IDKeys:           []string{"report_id", "id", "template_id", "resource_urn"},
				CursorParam:      "c",
				NextCursorKeys:   []string{"pagination.next_cursor", "pagination.cursor", "pagination.next"},
				PageSizeParams:   []string{"l"},
				ListKeys:         []string{"reports"},
				TimestampKeys:    []string{"generation_date", "updated_at", "created_at"},
				Attributes:       map[string]string{"evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "id": "report_id|id", "name": "template_name|report_id|id", "observed_at": "generation_date|updated_at|created_at", "resource_id": "report_id|id", "resource_name": "template_name|report_id|id", "resource_type": "report", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "event_id|report_id|id|metadata.event_id", "status": "status", "template_id": "template_id", "tenant_id": "tenant_id|metadata.tenant_id"},
				StaticAttributes: map[string]string{"record_class": "asset", "resource_type": "report", "schema": "reports", "source_system": "acunetix"},
			},
		},
	})
	if err != nil {
		return nil, err
	}
	return &Source{inner: inner}, nil
}

func (s *Source) Spec() *cerebrov1.SourceSpec {
	if s == nil || s.inner == nil {
		return nil
	}
	return s.inner.Spec()
}

func (s *Source) Check(ctx context.Context, cfg sourcecdk.Config) error {
	runtimeCfg, err := s.runtimeConfig(ctx, cfg)
	if err != nil {
		return err
	}
	if err := s.checkHealth(ctx, runtimeCfg); err != nil {
		return err
	}
	return s.inner.Check(ctx, runtimeCfg)
}

func (s *Source) Discover(ctx context.Context, cfg sourcecdk.Config) ([]sourcecdk.URN, error) {
	runtimeCfg, err := s.runtimeConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}
	return s.inner.Discover(ctx, runtimeCfg)
}

func (s *Source) Read(ctx context.Context, cfg sourcecdk.Config, cursor *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
	runtimeCfg, err := s.runtimeConfig(ctx, cfg)
	if err != nil {
		return sourcecdk.Pull{}, err
	}
	return s.inner.Read(ctx, runtimeCfg, cursor)
}

func (s *Source) runtimeConfig(_ context.Context, cfg sourcecdk.Config) (sourcecdk.Config, error) {
	return sourcecdk.ResolveBaseURLConfig(sourceID, defaultBaseURLTemplate, cfg, templateKeys)
}

func (s *Source) checkHealth(ctx context.Context, cfg sourcecdk.Config) error {
	path := firstNonEmpty(sourcecdk.ConfigValue(cfg, "health_path"), defaultHealthPath)
	return s.inner.CheckPath(ctx, cfg, path, nil)
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

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func (s *Source) allowLoopbackForTest() {
	if s != nil && s.inner != nil {
		s.inner.AllowLoopbackBaseURL = true
		s.allowLoopback = true
	}
}
