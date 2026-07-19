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
		ConfigurableAuthModels: []string{
			"none",
			"api_key",
		},
		Families: []jsonapi.Family{
			{
				Name:             familyAggregate,
				Path:             "/${config.source}/aggregates",
				URNKind:          "opendatasoft_aggregate",
				IDKeys:           []string{"count(*)", "id", "event_id", "uuid", "request_id"},
				PageSizeParams:   []string{"limit"},
				ListKeys:         []string{"aggregations"},
				TimestampKeys:    []string{"observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"actor_email": "actor_email|actor.email|email|user.email", "actor_id": "actor_id|actor.id|actorId|user_id|user.id", "actor_name": "actor_name|actor.name|user.name", "event_type": "event_type|event_name|action|type", "evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "id": "count(*)|id", "observed_at": "observed_at|updated_at|last_seen_at", "provider_id": "count(*)|id", "resource_email": "resource_email|target_email|target.email", "resource_id": "count(*)|resource_id|target_id|target.id|resource.id|object_id", "resource_name": "count(*)|resource_name|target_name|target.name|resource.name|object_name", "resource_type": "resource_type|target_type|target.type|object_type", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "event_id|count(*)|id|metadata.event_id", "tenant_id": "tenant_id|metadata.tenant_id"},
				StaticAttributes: map[string]string{"actor_id": "public.opendatasoft.com", "event_type": "aggregate", "record_class": "audit_event", "resource_type": "aggregate", "schema": "aggregate", "source_system": "opendatasoft"},
				Config: jsonapi.FamilyConfig{
					ConfigAttributes: map[string]string{"tenant_id": "tenant_id"},
					ConfigQuery:      map[string]string{"select": "select"},
				},
			},
			{
				Name:             familyPage,
				Path:             "/pages",
				URNKind:          "opendatasoft_page",
				IDKeys:           []string{"page.slug", "page.title.en", "page.title.fr", "id", "urn", "resource_urn", "name"},
				ListKeys:         []string{"pages"},
				TimestampKeys:    []string{"observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "id": "page.slug", "name": "page.title.en|page.title.fr|page.slug", "observed_at": "observed_at|updated_at|last_seen_at", "resource_id": "page.slug", "resource_name": "page.title.en|page.title.fr|page.slug", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "event_id|page.slug|id|metadata.event_id", "tenant_id": "tenant_id|metadata.tenant_id"},
				StaticAttributes: map[string]string{"record_class": "asset", "resource_type": "page", "schema": "page", "source_system": "opendatasoft"},
				Config: jsonapi.FamilyConfig{
					ConfigAttributes: map[string]string{"tenant_id": "tenant_id"},
					EncodeURNID:      true,
					ResourceURNKind:  "opendatasoft_page",
				},
			},
			{
				Name:             familyDataset,
				Path:             "/${config.source}/datasets",
				URNKind:          "opendatasoft_dataset",
				IDKeys:           []string{"dataset.dataset_id", "dataset.dataset_uid", "event_id", "id", "uuid", "request_id"},
				PageSizeParams:   []string{"limit"},
				ListKeys:         []string{"datasets"},
				TimestampKeys:    []string{"observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"actor_email": "actor_email|actor.email|email|user.email", "actor_id": "actor_id|actor.id|actorId|user_id|user.id", "actor_name": "actor_name|actor.name|user.name", "event_type": "event_type|event_name|action|type", "evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "id": "dataset.dataset_id|dataset.dataset_uid", "name": "dataset.metas.default.title|dataset.dataset_id", "observed_at": "dataset.metas.default.modified|dataset.metas.default.metadata_processed|dataset.metas.default.data_processed|observed_at|updated_at|last_seen_at", "provider_id": "dataset.dataset_id|dataset.dataset_uid", "resource_email": "resource_email|target_email|target.email", "resource_id": "dataset.dataset_id|resource_id|target_id|target.id|resource.id|object_id", "resource_name": "dataset.metas.default.title|dataset.dataset_id|resource_name|target_name|target.name|resource.name|object_name", "resource_type": "resource_type|target_type|target.type|object_type", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "event_id|dataset.dataset_id|dataset.dataset_uid|id|metadata.event_id", "tenant_id": "tenant_id|metadata.tenant_id"},
				StaticAttributes: map[string]string{"actor_id": "public.opendatasoft.com", "event_type": "dataset", "record_class": "audit_event", "resource_type": "dataset", "schema": "dataset", "source_system": "opendatasoft"},
				Config: jsonapi.FamilyConfig{
					ConfigAttributes: map[string]string{"tenant_id": "tenant_id"},
				},
			},
			{
				Name:             familyFacet,
				Path:             "/${config.source}/facets",
				URNKind:          "opendatasoft_facet",
				IDKeys:           []string{"name", "event_id", "id", "uuid", "request_id"},
				ListKeys:         []string{"facets"},
				TimestampKeys:    []string{"observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"actor_email": "actor_email|actor.email|email|user.email", "actor_id": "actor_id|actor.id|actorId|user_id|user.id", "actor_name": "actor_name|actor.name|user.name", "event_type": "event_type|event_name|action|type", "evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "id": "name", "name": "name", "observed_at": "observed_at|updated_at|last_seen_at", "provider_id": "name", "resource_email": "resource_email|target_email|target.email", "resource_id": "resource_id|target_id|target.id|resource.id|object_id", "resource_name": "resource_name|target_name|target.name|resource.name|object_name", "resource_type": "resource_type|target_type|target.type|object_type", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "event_id|name|id|metadata.event_id", "tenant_id": "tenant_id|metadata.tenant_id"},
				StaticAttributes: map[string]string{"actor_id": "public.opendatasoft.com", "event_type": "facet", "record_class": "audit_event", "resource_type": "facet", "schema": "facet", "source_system": "opendatasoft"},
				Config: jsonapi.FamilyConfig{
					ConfigAttributes: map[string]string{"tenant_id": "tenant_id"},
				},
			},
			{
				Name:             familyResource,
				Path:             "/${config.source}",
				URNKind:          "opendatasoft_resource",
				IDKeys:           []string{"rel", "href", "event_id", "id", "uuid", "request_id"},
				ListKeys:         []string{"links"},
				TimestampKeys:    []string{"observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"actor_email": "actor_email|actor.email|email|user.email", "actor_id": "actor_id|actor.id|actorId|user_id|user.id", "actor_name": "actor_name|actor.name|user.name", "event_type": "event_type|event_name|action|type", "evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "id": "rel|href", "name": "rel|href", "observed_at": "observed_at|updated_at|last_seen_at", "provider_id": "rel|href", "resource_email": "resource_email|target_email|target.email", "resource_id": "rel|href|resource_id|target_id|target.id|resource.id|object_id", "resource_name": "rel|href|resource_name|target_name|target.name|resource.name|object_name", "resource_type": "resource_type|target_type|target.type|object_type", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "event_id|rel|href|id|metadata.event_id", "tenant_id": "tenant_id|metadata.tenant_id"},
				StaticAttributes: map[string]string{"actor_id": "public.opendatasoft.com", "event_type": "resource", "record_class": "audit_event", "resource_type": "resource", "schema": "resource", "source_system": "opendatasoft"},
				Config: jsonapi.FamilyConfig{
					ConfigAttributes: map[string]string{"tenant_id": "tenant_id"},
				},
			},
			{
				Name:             familyResource2,
				Path:             "/",
				URNKind:          "opendatasoft_resource_2",
				IDKeys:           []string{"rel", "href", "id", "urn", "resource_urn", "name"},
				ListKeys:         []string{"links"},
				TimestampKeys:    []string{"observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "id": "rel|href", "name": "rel|href", "observed_at": "observed_at|updated_at|last_seen_at", "resource_id": "rel|href", "resource_name": "rel|href", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "event_id|rel|href|id|metadata.event_id", "tenant_id": "tenant_id|metadata.tenant_id"},
				StaticAttributes: map[string]string{"record_class": "asset", "resource_type": "resource", "schema": "resource_2", "source_system": "opendatasoft"},
				Config: jsonapi.FamilyConfig{
					ConfigAttributes: map[string]string{"tenant_id": "tenant_id"},
					EncodeURNID:      true,
					ResourceURNKind:  "opendatasoft_resource_2",
				},
			},
			{
				Name:             familyMetadataTemplate,
				Path:             "/${config.source}/metadata_templates",
				URNKind:          "opendatasoft_metadata_template",
				IDKeys:           []string{"rel", "href", "id", "urn", "resource_urn", "name"},
				ListKeys:         []string{"links"},
				TimestampKeys:    []string{"observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "id": "rel|href", "name": "rel|href", "observed_at": "observed_at|updated_at|last_seen_at", "resource_id": "rel|href", "resource_name": "rel|href", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "event_id|rel|href|id|metadata.event_id", "tenant_id": "tenant_id|metadata.tenant_id"},
				StaticAttributes: map[string]string{"record_class": "asset", "resource_type": "metadata_template", "schema": "metadata_template", "source_system": "opendatasoft"},
				Config: jsonapi.FamilyConfig{
					ConfigAttributes: map[string]string{"tenant_id": "tenant_id"},
					EncodeURNID:      true,
					ResourceURNKind:  "opendatasoft_metadata_template",
				},
			},
			{
				Name:             familyDatasetsAggregate,
				Path:             "/${config.source}/datasets/${config.dataset_id}/aggregates",
				URNKind:          "opendatasoft_datasets_aggregate",
				IDKeys:           []string{"count(*)", "id", "urn", "resource_urn", "name"},
				PageSizeParams:   []string{"limit"},
				ListKeys:         []string{"aggregations"},
				TimestampKeys:    []string{"observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "id": "count(*)|id", "observed_at": "observed_at|updated_at|last_seen_at", "resource_id": "count(*)|id", "resource_name": "count(*)|id", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "event_id|count(*)|id|metadata.event_id", "tenant_id": "tenant_id|metadata.tenant_id"},
				StaticAttributes: map[string]string{"record_class": "asset", "resource_type": "aggregate", "schema": "datasets_aggregate", "source_system": "opendatasoft"},
				Config: jsonapi.FamilyConfig{
					ConfigAttributes: map[string]string{"tenant_id": "tenant_id"},
					ConfigQuery:      map[string]string{"select": "select"},
					EncodeURNID:      true,
					ResourceURNKind:  "opendatasoft_datasets_aggregate",
				},
			},
			{
				Name:             familyAttachment,
				Path:             "/${config.source}/datasets/${config.dataset_id}/attachments",
				URNKind:          "opendatasoft_attachment",
				IDKeys:           []string{"metas.id", "href", "id", "urn", "resource_urn", "name"},
				ListKeys:         []string{"attachments"},
				TimestampKeys:    []string{"observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "id": "metas.id|href", "name": "metas.title|metas.id|href", "observed_at": "observed_at|updated_at|last_seen_at", "resource_id": "metas.id|href", "resource_name": "metas.title|metas.id|href", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "event_id|metas.id|href|id|metadata.event_id", "tenant_id": "tenant_id|metadata.tenant_id"},
				StaticAttributes: map[string]string{"record_class": "asset", "resource_type": "attachment", "schema": "attachment", "source_system": "opendatasoft"},
				Config: jsonapi.FamilyConfig{
					ConfigAttributes: map[string]string{"tenant_id": "tenant_id"},
					EncodeURNID:      true,
					ResourceURNKind:  "opendatasoft_attachment",
				},
			},
			{
				Name:             familyDatasetsFacet,
				Path:             "/${config.source}/datasets/${config.dataset_id}/facets",
				URNKind:          "opendatasoft_datasets_facet",
				IDKeys:           []string{"name", "id", "urn", "resource_urn"},
				ListKeys:         []string{"facets"},
				TimestampKeys:    []string{"observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "id": "name", "name": "name", "observed_at": "observed_at|updated_at|last_seen_at", "resource_id": "name", "resource_name": "name", "resource_type": "facet", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "event_id|name|id|metadata.event_id", "tenant_id": "tenant_id|metadata.tenant_id"},
				StaticAttributes: map[string]string{"record_class": "asset", "resource_type": "facet", "schema": "datasets_facet", "source_system": "opendatasoft"},
				Config: jsonapi.FamilyConfig{
					ConfigAttributes: map[string]string{"tenant_id": "tenant_id"},
					EncodeURNID:      true,
					ResourceURNKind:  "opendatasoft_datasets_facet",
				},
			},
			{
				Name:             familyRecord,
				Path:             "/${config.source}/datasets/${config.dataset_id}/records",
				URNKind:          "opendatasoft_record",
				IDKeys:           []string{"record.id", "record.fields.code_rome", "record.fields.libelle", "id", "urn", "resource_urn", "name"},
				PageSizeParams:   []string{"limit"},
				ListKeys:         []string{"records"},
				TimestampKeys:    []string{"observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "id": "record.id", "name": "record.fields.libelle|record.id", "observed_at": "record.timestamp|observed_at|updated_at|last_seen_at", "resource_id": "record.id", "resource_name": "record.fields.libelle|record.id", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "event_id|record.id|id|metadata.event_id", "tenant_id": "tenant_id|metadata.tenant_id"},
				StaticAttributes: map[string]string{"record_class": "asset", "resource_type": "record", "schema": "record", "source_system": "opendatasoft"},
				Config: jsonapi.FamilyConfig{
					ConfigAttributes: map[string]string{"tenant_id": "tenant_id"},
					EncodeURNID:      true,
					ResourceURNKind:  "opendatasoft_record",
				},
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
				StaticAttributes: map[string]string{"record_class": "asset", "resource_type": "reuses", "schema": "reuses", "source_system": "opendatasoft"},
				Config: jsonapi.FamilyConfig{
					ConfigAttributes: map[string]string{"tenant_id": "tenant_id"},
					EncodeURNID:      true,
					ResourceURNKind:  "opendatasoft_reuses",
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
