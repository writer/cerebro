package opendatasoft

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
	sourceID                = "opendatasoft"
	defaultFamily           = familyAggregate
	defaultHealthPath       = "/${config.source}/aggregates"
	defaultBaseURLTemplate  = "https://public.opendatasoft.com/api/v2"
	tokenHeader             = ""
	tokenScheme             = "Token"
	familyAggregate         = "aggregate"
	familyPage              = "page"
	familyDataset           = "dataset"
	familyFacet             = "facet"
	familyResource          = "resource"
	familyResource2         = "resource_2"
	familyMetadataTemplate  = "metadata_template"
	familyDatasetsAggregate = "datasets_aggregate"
	familyAttachment        = "attachment"
	familyDatasetsFacet     = "datasets_facet"
	familyRecord            = "record"
	familyReuses            = "reuses"
)

var templateKeys = []string{"dataset_id", "source", "api_key"}

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
				Name:             familyAggregate,
				Path:             "/${config.source}/aggregates",
				URNKind:          "opendatasoft_aggregate",
				IDKeys:           []string{"id", "event_id", "uuid", "request_id"},
				PageSizeParams:   []string{"limit"},
				ListKeys:         []string{"aggregations"},
				TimestampKeys:    []string{"observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"actor_email": "actor_email|actor.email|email|user.email", "actor_id": "actor_id|actor.id|actorId|user_id|user.id", "actor_name": "actor_name|actor.name|user.name", "event_type": "event_type|event_name|action|type", "evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "id": "id", "observed_at": "observed_at|updated_at|last_seen_at", "provider_id": "id", "resource_email": "resource_email|target_email|target.email", "resource_id": "resource_id|target_id|target.id|resource.id|object_id", "resource_name": "resource_name|target_name|target.name|resource.name|object_name", "resource_type": "resource_type|target_type|target.type|object_type", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "event_id|id|metadata.event_id", "tenant_id": "tenant_id|metadata.tenant_id"},
				StaticAttributes: map[string]string{"record_class": "audit_event", "schema": "aggregate", "source_system": "opendatasoft"},
			},
			{
				Name:             familyPage,
				Path:             "/pages",
				URNKind:          "opendatasoft_page",
				IDKeys:           []string{"links", "id", "urn", "resource_urn", "name"},
				ListKeys:         []string{"pages"},
				TimestampKeys:    []string{"observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "id": "links", "name": "links", "observed_at": "observed_at|updated_at|last_seen_at", "resource_id": "links", "resource_name": "links", "resource_type": "page", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "event_id|id|metadata.event_id", "tenant_id": "tenant_id|metadata.tenant_id"},
				StaticAttributes: map[string]string{"record_class": "asset", "schema": "page", "source_system": "opendatasoft"},
			},
			{
				Name:             familyDataset,
				Path:             "/${config.source}/datasets",
				URNKind:          "opendatasoft_dataset",
				IDKeys:           []string{"dataset", "event_id", "id", "uuid", "request_id"},
				PageSizeParams:   []string{"limit"},
				ListKeys:         []string{"datasets"},
				TimestampKeys:    []string{"observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"actor_email": "actor_email|actor.email|email|user.email", "actor_id": "actor_id|actor.id|actorId|user_id|user.id", "actor_name": "actor_name|actor.name|user.name", "event_type": "event_type|event_name|action|type", "evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "id": "dataset", "name": "dataset", "observed_at": "observed_at|updated_at|last_seen_at", "provider_id": "dataset", "resource_email": "resource_email|target_email|target.email", "resource_id": "resource_id|target_id|target.id|resource.id|object_id", "resource_name": "resource_name|target_name|target.name|resource.name|object_name", "resource_type": "resource_type|target_type|target.type|object_type", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "event_id|id|metadata.event_id", "tenant_id": "tenant_id|metadata.tenant_id"},
				StaticAttributes: map[string]string{"record_class": "audit_event", "schema": "dataset", "source_system": "opendatasoft"},
			},
			{
				Name:             familyFacet,
				Path:             "/${config.source}/facets",
				URNKind:          "opendatasoft_facet",
				IDKeys:           []string{"name", "event_id", "id", "uuid", "request_id"},
				ListKeys:         []string{"facets"},
				TimestampKeys:    []string{"observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"actor_email": "actor_email|actor.email|email|user.email", "actor_id": "actor_id|actor.id|actorId|user_id|user.id", "actor_name": "actor_name|actor.name|user.name", "event_type": "event_type|event_name|action|type", "evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "id": "name", "name": "name", "observed_at": "observed_at|updated_at|last_seen_at", "provider_id": "name", "resource_email": "resource_email|target_email|target.email", "resource_id": "resource_id|target_id|target.id|resource.id|object_id", "resource_name": "resource_name|target_name|target.name|resource.name|object_name", "resource_type": "resource_type|target_type|target.type|object_type", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "event_id|id|metadata.event_id", "tenant_id": "tenant_id|metadata.tenant_id"},
				StaticAttributes: map[string]string{"record_class": "audit_event", "schema": "facet", "source_system": "opendatasoft"},
			},
			{
				Name:             familyResource,
				Path:             "/${config.source}",
				URNKind:          "opendatasoft_resource",
				IDKeys:           []string{"href", "event_id", "id", "uuid", "request_id"},
				ListKeys:         []string{"links"},
				TimestampKeys:    []string{"observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"actor_email": "actor_email|actor.email|email|user.email", "actor_id": "actor_id|actor.id|actorId|user_id|user.id", "actor_name": "actor_name|actor.name|user.name", "event_type": "event_type|event_name|action|type", "evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "id": "href", "name": "href", "observed_at": "observed_at|updated_at|last_seen_at", "provider_id": "href", "resource_email": "resource_email|target_email|target.email", "resource_id": "resource_id|target_id|target.id|resource.id|object_id", "resource_name": "resource_name|target_name|target.name|resource.name|object_name", "resource_type": "resource_type|target_type|target.type|object_type", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "event_id|id|metadata.event_id", "tenant_id": "tenant_id|metadata.tenant_id"},
				StaticAttributes: map[string]string{"record_class": "audit_event", "schema": "resource", "source_system": "opendatasoft"},
			},
			{
				Name:             familyResource2,
				Path:             "/",
				URNKind:          "opendatasoft_resource_2",
				IDKeys:           []string{"href", "id", "urn", "resource_urn", "name"},
				ListKeys:         []string{"links"},
				TimestampKeys:    []string{"observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "id": "href", "name": "href", "observed_at": "observed_at|updated_at|last_seen_at", "resource_id": "href", "resource_name": "href", "resource_type": "resource", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "event_id|id|metadata.event_id", "tenant_id": "tenant_id|metadata.tenant_id"},
				StaticAttributes: map[string]string{"record_class": "asset", "schema": "resource_2", "source_system": "opendatasoft"},
			},
			{
				Name:             familyMetadataTemplate,
				Path:             "/${config.source}/metadata_templates",
				URNKind:          "opendatasoft_metadata_template",
				IDKeys:           []string{"href", "id", "urn", "resource_urn", "name"},
				ListKeys:         []string{"links"},
				TimestampKeys:    []string{"observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "id": "href", "name": "href", "observed_at": "observed_at|updated_at|last_seen_at", "resource_id": "href", "resource_name": "href", "resource_type": "metadata_template", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "event_id|id|metadata.event_id", "tenant_id": "tenant_id|metadata.tenant_id"},
				StaticAttributes: map[string]string{"record_class": "asset", "schema": "metadata_template", "source_system": "opendatasoft"},
			},
			{
				Name:             familyDatasetsAggregate,
				Path:             "/${config.source}/datasets/${config.dataset_id}/aggregates",
				URNKind:          "opendatasoft_datasets_aggregate",
				IDKeys:           []string{"id", "urn", "resource_urn", "name"},
				PageSizeParams:   []string{"limit"},
				ListKeys:         []string{"aggregations"},
				TimestampKeys:    []string{"observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "id": "id", "observed_at": "observed_at|updated_at|last_seen_at", "resource_id": "id", "resource_name": "id", "resource_type": "aggregate", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "event_id|id|metadata.event_id", "tenant_id": "tenant_id|metadata.tenant_id"},
				StaticAttributes: map[string]string{"record_class": "asset", "schema": "datasets_aggregate", "source_system": "opendatasoft"},
			},
			{
				Name:             familyAttachment,
				Path:             "/${config.source}/datasets/${config.dataset_id}/attachments",
				URNKind:          "opendatasoft_attachment",
				IDKeys:           []string{"href", "id", "urn", "resource_urn", "name"},
				ListKeys:         []string{"attachments"},
				TimestampKeys:    []string{"observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "id": "href", "name": "href", "observed_at": "observed_at|updated_at|last_seen_at", "resource_id": "href", "resource_name": "href", "resource_type": "attachment", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "event_id|id|metadata.event_id", "tenant_id": "tenant_id|metadata.tenant_id"},
				StaticAttributes: map[string]string{"record_class": "asset", "schema": "attachment", "source_system": "opendatasoft"},
			},
			{
				Name:             familyDatasetsFacet,
				Path:             "/${config.source}/datasets/${config.dataset_id}/facets",
				URNKind:          "opendatasoft_datasets_facet",
				IDKeys:           []string{"name", "id", "urn", "resource_urn"},
				ListKeys:         []string{"facets"},
				TimestampKeys:    []string{"observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "id": "name", "name": "name", "observed_at": "observed_at|updated_at|last_seen_at", "resource_id": "name", "resource_name": "name", "resource_type": "facet", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "event_id|id|metadata.event_id", "tenant_id": "tenant_id|metadata.tenant_id"},
				StaticAttributes: map[string]string{"record_class": "asset", "schema": "datasets_facet", "source_system": "opendatasoft"},
			},
			{
				Name:             familyRecord,
				Path:             "/${config.source}/datasets/${config.dataset_id}/records",
				URNKind:          "opendatasoft_record",
				IDKeys:           []string{"links", "id", "urn", "resource_urn", "name"},
				PageSizeParams:   []string{"limit"},
				ListKeys:         []string{"records"},
				TimestampKeys:    []string{"observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "id": "links", "name": "links", "observed_at": "observed_at|updated_at|last_seen_at", "resource_id": "links", "resource_name": "links", "resource_type": "record", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "event_id|id|metadata.event_id", "tenant_id": "tenant_id|metadata.tenant_id"},
				StaticAttributes: map[string]string{"record_class": "asset", "schema": "record", "source_system": "opendatasoft"},
			},
			{
				Name:             familyReuses,
				Path:             "/${config.source}/datasets/${config.dataset_id}/reuses",
				URNKind:          "opendatasoft_reuses",
				IDKeys:           []string{"id", "title", "urn", "resource_urn", "name"},
				PageSizeParams:   []string{"limit"},
				ListKeys:         []string{"reuses"},
				TimestampKeys:    []string{"observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "id": "id", "name": "title", "observed_at": "observed_at|updated_at|last_seen_at", "resource_id": "id", "resource_name": "title", "resource_type": "reuses", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "event_id|id|metadata.event_id", "tenant_id": "tenant_id|metadata.tenant_id"},
				StaticAttributes: map[string]string{"record_class": "asset", "schema": "reuses", "source_system": "opendatasoft"},
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
