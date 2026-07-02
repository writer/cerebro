package snyk

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
	sourceID               = "snyk"
	defaultFamily          = familyOrgs
	defaultAPIVersion      = "2026-03-25"
	defaultHealthPath      = "/orgs?version=" + defaultAPIVersion
	defaultBaseURLTemplate = "https://api.snyk.io/rest"
	tokenScheme            = "Token"
	apiVersionConfig       = "api_version"
	orgIDConfig            = "org_id"
	familyOrgs             = "orgs"
	familyGroups           = "groups"
	familyProjects         = "projects"
	familyTargets          = "targets"
	familyAssets           = "assets"
	familyFindings         = "findings"
	familyVulnerabilities  = "vulnerabilities"
)

type Source struct {
	inner *jsonapi.Source
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
		AuthModel:       "api_token",
		TokenScheme:     tokenScheme,
		Families: []jsonapi.Family{
			snykPagedFamily(jsonapi.Family{
				Name:          familyOrgs,
				Path:          "/orgs",
				URNKind:       "snyk_orgs",
				IDKeys:        []string{"id"},
				ListKeys:      []string{"data"},
				TimestampKeys: []string{"attributes.created_at", "attributes.updated_at"},
				Attributes:    map[string]string{"org_id": "id", "name": "attributes.name|name", "slug": "attributes.slug", "group_id": "relationships.group.data.id", "created_at": "attributes.created_at", "updated_at": "attributes.updated_at", "source_event_id": "id"},
				StaticAttributes: map[string]string{
					"record_class":  "asset",
					"resource_type": "snyk_org",
					"schema":        "orgs",
					"source_system": "snyk",
				},
			}),
			snykPagedFamily(jsonapi.Family{
				Name:          familyGroups,
				Path:          "/groups",
				URNKind:       "snyk_groups",
				IDKeys:        []string{"id"},
				ListKeys:      []string{"data"},
				TimestampKeys: []string{"attributes.created_at", "attributes.updated_at"},
				Attributes:    map[string]string{"group_id": "id", "name": "attributes.name|name", "slug": "attributes.slug", "created_at": "attributes.created_at", "updated_at": "attributes.updated_at", "source_event_id": "id"},
				StaticAttributes: map[string]string{
					"record_class":  "asset",
					"resource_type": "snyk_group",
					"schema":        "groups",
					"source_system": "snyk",
				},
			}),
			snykOrgPagedFamily(jsonapi.Family{
				Name:             familyProjects,
				Path:             "/orgs/{org_id}/projects",
				PathParams:       []string{orgIDConfig},
				URNKind:          "snyk_projects",
				IDKeys:           []string{"id"},
				ListKeys:         []string{"data"},
				TimestampKeys:    []string{"attributes.created", "attributes.created_at", "attributes.updated_at"},
				Attributes:       map[string]string{"org_id": orgIDConfig, "project_id": "id", "name": "attributes.name|name", "origin": "attributes.origin", "type": "attributes.type", "target_id": "relationships.target.data.id|attributes.target_id", "created_at": "attributes.created|attributes.created_at", "updated_at": "attributes.updated_at", "source_event_id": "id", "resource_id": "id", "resource_name": "attributes.name|name"},
				StaticAttributes: map[string]string{"record_class": "asset", "resource_type": "snyk_project", "schema": "projects", "source_system": "snyk"},
			}),
			snykOrgPagedFamily(jsonapi.Family{
				Name:             familyTargets,
				Path:             "/orgs/{org_id}/targets",
				PathParams:       []string{orgIDConfig},
				URNKind:          "snyk_targets",
				IDKeys:           []string{"id"},
				ListKeys:         []string{"data"},
				TimestampKeys:    []string{"attributes.created_at", "attributes.updated_at"},
				Attributes:       map[string]string{"org_id": orgIDConfig, "target_id": "id", "display_name": "attributes.display_name|attributes.name|name", "url": "attributes.url", "source_type": "attributes.source_type", "is_private": "attributes.is_private", "created_at": "attributes.created_at", "updated_at": "attributes.updated_at", "source_event_id": "id", "resource_id": "id", "resource_name": "attributes.display_name|attributes.name|name"},
				StaticAttributes: map[string]string{"record_class": "asset", "resource_type": "snyk_target", "schema": "targets", "source_system": "snyk"},
			}),
			{
				Name:             familyAssets,
				Path:             "/orgs/{org_id}/inventory/assets",
				PathParams:       []string{orgIDConfig},
				URNKind:          "snyk_assets",
				IDKeys:           []string{"id", "urn", "resource_urn", "name"},
				CursorParam:      "starting_after",
				NextCursorKeys:   []string{"links.next"},
				PageSizeParams:   []string{"limit"},
				ListKeys:         []string{"data"},
				TimestampKeys:    []string{"attributes.updated_at", "attributes.created_at", "observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"org_id": orgIDConfig, "asset_id": "id", "evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "observed_at": "attributes.updated_at|observed_at|updated_at|last_seen_at", "resource_id": "id", "resource_name": "attributes.name|attributes.display_name|name|display_name|hostname|metadata.resource_name", "resource_type": "attributes.type|resource_type|type|kind", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "event_id|id|metadata.event_id", "tenant_id": "tenant_id|metadata.tenant_id"},
				StaticAttributes: map[string]string{"record_class": "asset", "schema": "assets", "source_system": "snyk"},
				Config:           snykVersionedConfig(),
			},
			{
				Name:             familyFindings,
				Path:             "/orgs/{org_id}/issues",
				PathParams:       []string{orgIDConfig},
				URNKind:          "snyk_findings",
				IDKeys:           []string{"id", "finding_id", "resource_urn"},
				CursorParam:      "starting_after",
				NextCursorKeys:   []string{"links.next"},
				PageSizeParams:   []string{"limit"},
				ListKeys:         []string{"data"},
				TimestampKeys:    []string{"attributes.updated_at", "attributes.created_at", "attributes.discovered_at", "observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"org_id": orgIDConfig, "description": "attributes.description|attributes.summary|description|summary", "evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "finding_id": "id", "issue_type": "attributes.type|type", "observed_at": "attributes.updated_at|attributes.discovered_at|observed_at|updated_at|last_seen_at", "resource_id": "relationships.scan_item.data.id|attributes.scan_item.id|resource_id|metadata.resource_id", "resource_name": "attributes.scan_item.name|attributes.package.name|name|display_name|hostname|metadata.resource_name", "resource_type": "relationships.scan_item.data.type|attributes.scan_item.type|resource_type|type|metadata.resource_type", "resource_urn": "resource_urn|urn|metadata.resource_urn", "severity": "attributes.effective_severity_level|attributes.severity|severity|risk|priority", "source_event_id": "event_id|id|metadata.event_id", "status": "attributes.status|status|state", "tenant_id": "tenant_id|metadata.tenant_id", "title": "attributes.title|attributes.key|title|name|summary"},
				StaticAttributes: map[string]string{"record_class": "finding", "schema": "findings", "source_system": "snyk"},
				Config:           snykVersionedConfig(),
			},
			{
				Name:             familyVulnerabilities,
				Path:             "/orgs/{org_id}/issues",
				PathParams:       []string{orgIDConfig},
				URNKind:          "snyk_vulnerabilities",
				IDKeys:           []string{"id", "finding_id", "resource_urn"},
				CursorParam:      "starting_after",
				NextCursorKeys:   []string{"links.next"},
				PageSizeParams:   []string{"limit"},
				ListKeys:         []string{"data"},
				TimestampKeys:    []string{"attributes.updated_at", "attributes.created_at", "attributes.discovered_at", "observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"org_id": orgIDConfig, "description": "attributes.description|attributes.summary|description|summary", "evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "finding_id": "id", "issue_type": "attributes.type|type", "observed_at": "attributes.updated_at|attributes.discovered_at|observed_at|updated_at|last_seen_at", "resource_id": "relationships.scan_item.data.id|attributes.scan_item.id|resource_id|metadata.resource_id", "resource_name": "attributes.scan_item.name|attributes.package.name|name|display_name|hostname|metadata.resource_name", "resource_type": "relationships.scan_item.data.type|attributes.scan_item.type|resource_type|type|metadata.resource_type", "resource_urn": "resource_urn|urn|metadata.resource_urn", "severity": "attributes.effective_severity_level|attributes.severity|severity|risk|priority", "source_event_id": "event_id|id|metadata.event_id", "status": "attributes.status|status|state", "tenant_id": "tenant_id|metadata.tenant_id", "title": "attributes.title|attributes.key|title|name|summary"},
				StaticAttributes: map[string]string{"record_class": "finding", "schema": "vulnerabilities", "source_system": "snyk"},
				Config: jsonapi.FamilyConfig{
					StaticQuery: map[string]string{"type": "package_vulnerability"},
					ConfigQuery: map[string]string{"version": apiVersionConfig},
				},
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
	runtimeCfg, err := sourcecdk.ResolveBaseURLConfig(sourceID, defaultBaseURLTemplate, cfg, []string{"token"})
	if err != nil {
		return sourcecdk.Config{}, err
	}
	values := runtimeCfg.Values()
	if strings.TrimSpace(values[apiVersionConfig]) == "" {
		values[apiVersionConfig] = defaultAPIVersion
	}
	return sourcecdk.NewConfig(values), nil
}

func (s *Source) checkHealth(ctx context.Context, cfg sourcecdk.Config) error {
	path := strings.TrimSpace(sourcecdk.ConfigValue(cfg, "health_path"))
	if path == "" {
		path = defaultHealthPath
	}
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

func (s *Source) allowLoopbackForTest() {
	if s != nil && s.inner != nil {
		s.inner.AllowLoopbackBaseURL = true
	}
}

func snykPagedFamily(family jsonapi.Family) jsonapi.Family {
	family.CursorParam = "starting_after"
	family.NextCursorKeys = []string{"links.next"}
	family.PageSizeParams = []string{"limit"}
	family.Config = snykVersionedConfig()
	return family
}

func snykOrgPagedFamily(family jsonapi.Family) jsonapi.Family {
	family = snykPagedFamily(family)
	family.Config.ConfigAttributes = map[string]string{"org_id": orgIDConfig}
	return family
}

func snykVersionedConfig() jsonapi.FamilyConfig {
	return jsonapi.FamilyConfig{ConfigQuery: map[string]string{"version": apiVersionConfig}}
}
