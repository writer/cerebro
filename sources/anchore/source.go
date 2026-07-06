package anchore

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
	sourceID               = "anchore"
	defaultFamily          = familyAssets
	defaultHealthPath      = "/system"
	defaultBaseURLTemplate = "https://${config.enterprise_url}/v2"
	tokenHeader            = ""
	tokenScheme            = ""
	familyAssets           = "assets"
	familyFindings         = "findings"
	familyVulnerabilities  = "vulnerabilities"
)

var templateKeys = []string{"app_id", "base_url", "enterprise_url", "password", "username", "version_id"}

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
		AuthModel:       "basic",
		TokenHeader:     tokenHeader,
		TokenScheme:     tokenScheme,
		Families: []jsonapi.Family{
			{
				Name:             familyAssets,
				Path:             "/apps/${config.app_id}/versions/${config.version_id}/assets",
				URNKind:          "anchore_assets",
				IDKeys:           []string{"system_metadata.id", "id", "name", "reference"},
				CursorParam:      "cursor",
				NextCursorKeys:   []string{"pagination.next_cursor"},
				PageSizeParams:   []string{"limit"},
				ListKeys:         []string{"items"},
				TimestampKeys:    []string{"system_metadata.updated_at", "system_metadata.created_at"},
				Attributes:       map[string]string{"app_id": "app_id", "asset_type": "type", "evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "observed_at": "system_metadata.updated_at|system_metadata.created_at", "reference": "reference", "resource_id": "system_metadata.id|id|name|reference", "resource_name": "name|reference|system_metadata.id", "resource_type": "type", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "system_metadata.id|id|name|reference", "tenant_id": "tenant_id|metadata.tenant_id", "version_id": "version_id"},
				StaticAttributes: map[string]string{"record_class": "asset", "schema": "assets", "source_system": "anchore"},
			},
			{
				Name:             familyFindings,
				Path:             "/apps/${config.app_id}/versions/${config.version_id}/policy/findings/all",
				URNKind:          "anchore_findings",
				IDKeys:           []string{"result.trigger_id", "rule.id", "id"},
				CursorParam:      "cursor",
				NextCursorKeys:   []string{"pagination.next_cursor"},
				PageSizeParams:   []string{"limit"},
				ListKeys:         []string{"items"},
				TimestampKeys:    []string{"observed_at", "updated_at", "created_at"},
				Attributes:       map[string]string{"action": "result.action", "assets_affected": "assets_affected", "description": "result.message|rule.recommendation|summary", "evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "finding_id": "result.trigger_id|rule.id|id", "observed_at": "observed_at|updated_at|created_at", "resource_id": "app_id", "resource_name": "version_id|app_id", "resource_type": "anchore_app_version", "resource_urn": "resource_urn|urn|metadata.resource_urn", "rule_gate": "rule.gate", "rule_id": "rule.id", "severity": "severity|risk|priority", "source_event_id": "result.trigger_id|rule.id|id", "status": "result.action|status|state", "tenant_id": "tenant_id|metadata.tenant_id", "title": "result.message|rule.id|title|name|summary"},
				StaticAttributes: map[string]string{"record_class": "finding", "schema": "findings", "source_system": "anchore"},
			},
			{
				Name:             familyVulnerabilities,
				Path:             "/apps/${config.app_id}/versions/${config.version_id}/vulnerabilities",
				URNKind:          "anchore_vulnerabilities",
				IDKeys:           []string{"vulnerability_id", "id", "purl"},
				CursorParam:      "cursor",
				NextCursorKeys:   []string{"pagination.next_cursor"},
				PageSizeParams:   []string{"limit"},
				ListKeys:         []string{"items"},
				TimestampKeys:    []string{"observed_at", "updated_at", "created_at"},
				Attributes:       map[string]string{"description": "description|summary", "evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "fix_state": "fix_state", "finding_id": "vulnerability_id|id", "observed_at": "observed_at|updated_at|created_at", "package_name": "package_name", "package_type": "package_type", "package_version": "package_version", "purl": "purl", "resource_id": "app_id", "resource_name": "package_name|vulnerability_id", "resource_type": "anchore_app_version", "resource_urn": "resource_urn|urn|metadata.resource_urn", "severity": "severity|risk|priority", "source_event_id": "vulnerability_id|id|purl", "status": "fix_state|vex_status|status|state", "tenant_id": "tenant_id|metadata.tenant_id", "title": "vulnerability_id|title|name|summary", "vex_status": "vex_status"},
				StaticAttributes: map[string]string{"record_class": "finding", "schema": "vulnerabilities", "source_system": "anchore"},
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
