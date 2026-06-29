package botify

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
	sourceID               = "botify"
	defaultFamily          = familyFilter
	defaultHealthPath      = "/projects/${config.username}/${config.project_slug}/filters"
	defaultBaseURLTemplate = "https://api.botify.com/v1"
	tokenHeader            = ""
	tokenScheme            = "Token"
	familyFilter           = "filter"
	familyExport           = "export"
	familyOutOfConfig      = "out_of_config"
	familySitemapOnly      = "sitemap_only"
	familyReport           = "report"
	familyProject          = "project"
	familyAnalyses         = "analyses"
	familyUrl              = "url"
	familyOrphanUrl        = "orphan_url"
	familyDatamodel        = "datamodel"
	familyDomain           = "domain"
	familyPercentile       = "percentile"
)

var templateKeys = []string{"analysis_slug", "list_type", "medium", "project_slug", "source", "username", "api_key"}

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
				Name:             familyFilter,
				Path:             "/projects/${config.username}/${config.project_slug}/filters",
				URNKind:          "botify_filter",
				IDKeys:           []string{"name", "id", "urn", "resource_urn"},
				ListKeys:         []string{"results"},
				TimestampKeys:    []string{"observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "id": "name", "name": "name", "observed_at": "observed_at|updated_at|last_seen_at", "resource_id": "name", "resource_name": "name", "resource_type": "filter", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "event_id|id|metadata.event_id", "tenant_id": "tenant_id|metadata.tenant_id"},
				StaticAttributes: map[string]string{"record_class": "asset", "schema": "filter", "source_system": "botify"},
			},
			{
				Name:             familyExport,
				Path:             "/analyses/${config.username}/${config.project_slug}/${config.analysis_slug}/urls/export",
				URNKind:          "botify_export",
				IDKeys:           []string{"area", "id", "urn", "resource_urn", "name"},
				ListKeys:         []string{"results"},
				TimestampKeys:    []string{"observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "id": "area", "name": "area", "observed_at": "observed_at|updated_at|last_seen_at", "resource_id": "area", "resource_name": "area", "resource_type": "export", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "event_id|id|metadata.event_id", "tenant_id": "tenant_id|metadata.tenant_id"},
				StaticAttributes: map[string]string{"record_class": "asset", "schema": "export", "source_system": "botify"},
			},
			{
				Name:             familyOutOfConfig,
				Path:             "/analyses/${config.username}/${config.project_slug}/${config.analysis_slug}/features/sitemaps/samples/out_of_config",
				URNKind:          "botify_out_of_config",
				IDKeys:           []string{"id", "urn", "resource_urn", "name"},
				ListKeys:         []string{"results"},
				TimestampKeys:    []string{"observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "id": "id", "observed_at": "observed_at|updated_at|last_seen_at", "resource_id": "id", "resource_name": "id", "resource_type": "out_of_config", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "event_id|id|metadata.event_id", "tenant_id": "tenant_id|metadata.tenant_id"},
				StaticAttributes: map[string]string{"record_class": "asset", "schema": "out_of_config", "source_system": "botify"},
			},
			{
				Name:             familySitemapOnly,
				Path:             "/analyses/${config.username}/${config.project_slug}/${config.analysis_slug}/features/sitemaps/samples/sitemap_only",
				URNKind:          "botify_sitemap_only",
				IDKeys:           []string{"id", "urn", "resource_urn", "name"},
				ListKeys:         []string{"results"},
				TimestampKeys:    []string{"observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "id": "id", "observed_at": "observed_at|updated_at|last_seen_at", "resource_id": "id", "resource_name": "id", "resource_type": "sitemap_only", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "event_id|id|metadata.event_id", "tenant_id": "tenant_id|metadata.tenant_id"},
				StaticAttributes: map[string]string{"record_class": "asset", "schema": "sitemap_only", "source_system": "botify"},
			},
			{
				Name:             familyReport,
				Path:             "/analyses/${config.username}/${config.project_slug}/${config.analysis_slug}/features/sitemaps/report",
				URNKind:          "botify_report",
				IDKeys:           []string{"error", "url", "id", "urn", "resource_urn", "name"},
				ListKeys:         []string{"errors"},
				TimestampKeys:    []string{"observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "id": "error", "name": "url", "observed_at": "observed_at|updated_at|last_seen_at", "resource_id": "error", "resource_name": "url", "resource_type": "report", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "event_id|id|metadata.event_id", "tenant_id": "tenant_id|metadata.tenant_id"},
				StaticAttributes: map[string]string{"record_class": "asset", "schema": "report", "source_system": "botify"},
			},
			{
				Name:             familyProject,
				Path:             "/projects/${config.username}",
				URNKind:          "botify_project",
				IDKeys:           []string{"slug", "name", "id", "urn", "resource_urn"},
				ListKeys:         []string{"results"},
				TimestampKeys:    []string{"observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "id": "slug", "name": "name", "observed_at": "observed_at|updated_at|last_seen_at", "resource_id": "slug", "resource_name": "name", "resource_type": "project", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "event_id|id|metadata.event_id", "tenant_id": "tenant_id|metadata.tenant_id"},
				StaticAttributes: map[string]string{"record_class": "asset", "schema": "project", "source_system": "botify"},
			},
			{
				Name:             familyAnalyses,
				Path:             "/analyses/${config.username}/${config.project_slug}",
				URNKind:          "botify_analyses",
				IDKeys:           []string{"id", "name", "urn", "resource_urn"},
				ListKeys:         []string{"results"},
				TimestampKeys:    []string{"observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "id": "id", "name": "name", "observed_at": "observed_at|updated_at|last_seen_at", "resource_id": "id", "resource_name": "name", "resource_type": "analyses", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "event_id|id|metadata.event_id", "tenant_id": "tenant_id|metadata.tenant_id"},
				StaticAttributes: map[string]string{"record_class": "asset", "schema": "analyses", "source_system": "botify"},
			},
			{
				Name:             familyUrl,
				Path:             "/analyses/${config.username}/${config.project_slug}/${config.analysis_slug}/crawl_statistics/urls/${config.list_type}",
				URNKind:          "botify_url",
				IDKeys:           []string{"id", "urn", "resource_urn", "name"},
				TimestampKeys:    []string{"observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "id": "id", "observed_at": "observed_at|updated_at|last_seen_at", "resource_id": "id", "resource_name": "id", "resource_type": "url", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "event_id|id|metadata.event_id", "tenant_id": "tenant_id|metadata.tenant_id"},
				StaticAttributes: map[string]string{"record_class": "asset", "schema": "url", "source_system": "botify"},
			},
			{
				Name:             familyOrphanUrl,
				Path:             "/analyses/${config.username}/${config.project_slug}/${config.analysis_slug}/features/ganalytics/orphan_urls/${config.medium}/${config.source}",
				URNKind:          "botify_orphan_url",
				IDKeys:           []string{"url", "id", "urn", "resource_urn", "name"},
				ListKeys:         []string{"results"},
				TimestampKeys:    []string{"observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "id": "url", "name": "url", "observed_at": "observed_at|updated_at|last_seen_at", "resource_id": "url", "resource_name": "url", "resource_type": "orphan_url", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "event_id|id|metadata.event_id", "tenant_id": "tenant_id|metadata.tenant_id"},
				StaticAttributes: map[string]string{"record_class": "asset", "schema": "orphan_url", "source_system": "botify"},
			},
			{
				Name:             familyDatamodel,
				Path:             "/analyses/${config.username}/${config.project_slug}/${config.analysis_slug}/urls/datamodel",
				URNKind:          "botify_datamodel",
				IDKeys:           []string{"id", "name", "urn", "resource_urn"},
				ListKeys:         []string{"fields"},
				TimestampKeys:    []string{"observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "id": "id", "name": "name", "observed_at": "observed_at|updated_at|last_seen_at", "resource_id": "id", "resource_name": "name", "resource_type": "datamodel", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "event_id|id|metadata.event_id", "tenant_id": "tenant_id|metadata.tenant_id"},
				StaticAttributes: map[string]string{"record_class": "asset", "schema": "datamodel", "source_system": "botify"},
			},
			{
				Name:             familyDomain,
				Path:             "/analyses/${config.username}/${config.project_slug}/${config.analysis_slug}/features/top_domains/domains",
				URNKind:          "botify_domain",
				IDKeys:           []string{"domain", "id", "urn", "resource_urn", "name"},
				ListKeys:         []string{"results"},
				TimestampKeys:    []string{"observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "id": "domain", "name": "domain", "observed_at": "observed_at|updated_at|last_seen_at", "resource_id": "domain", "resource_name": "domain", "resource_type": "domain", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "event_id|id|metadata.event_id", "tenant_id": "tenant_id|metadata.tenant_id"},
				StaticAttributes: map[string]string{"record_class": "asset", "schema": "domain", "source_system": "botify"},
			},
			{
				Name:             familyPercentile,
				Path:             "/analyses/${config.username}/${config.project_slug}/${config.analysis_slug}/features/links/percentiles",
				URNKind:          "botify_percentile",
				IDKeys:           []string{"id", "avg", "urn", "resource_urn", "name"},
				ListKeys:         []string{"percentiles"},
				TimestampKeys:    []string{"observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "id": "id", "name": "avg", "observed_at": "observed_at|updated_at|last_seen_at", "resource_id": "id", "resource_name": "avg", "resource_type": "percentile", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "event_id|id|metadata.event_id", "tenant_id": "tenant_id|metadata.tenant_id"},
				StaticAttributes: map[string]string{"record_class": "asset", "schema": "percentile", "source_system": "botify"},
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
