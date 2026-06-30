package google_gemini

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
	sourceID               = "google_gemini"
	defaultFamily          = familyModelCatalog
	defaultHealthPath      = "/v1beta/models"
	defaultBaseURLTemplate = "https://generativelanguage.googleapis.com"
	tokenHeader            = "x-goog-api-key"
	tokenScheme            = "Token"
	familyModelCatalog     = "model_catalog"
	familyTunedModels      = "tuned_models"
	familyFiles            = "files"
	familyCachedContents   = "cached_contents"
	familyBatchJobs        = "batch_jobs"
)

var templateKeys = []string{"api_key"}

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
				Name:             familyModelCatalog,
				Path:             "/v1beta/models",
				URNKind:          "google_gemini_model_catalog",
				IDKeys:           []string{"name", "displayName", "id", "urn", "resource_urn"},
				CursorParam:      "pageToken",
				NextCursorKeys:   []string{"nextPageToken"},
				PageSizeParams:   []string{"pageSize"},
				ListKeys:         []string{"models"},
				Config:           jsonapi.FamilyConfig{ResourceURNKind: "google_gemini_model_catalog"},
				TimestampKeys:    []string{"updateTime", "createTime", "observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "observed_at": "observed_at|updated_at|last_seen_at", "resource_id": "name", "resource_name": "displayName", "resource_type": "resource_type|type|kind", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "event_id|id|metadata.event_id", "tenant_id": "tenant_id|metadata.tenant_id"},
				StaticAttributes: map[string]string{"record_class": "asset", "resource_type": "model_catalog", "schema": "model_catalog", "source_system": "google_gemini"},
			},
			{
				Name:             familyTunedModels,
				Path:             "/v1beta/tunedModels",
				URNKind:          "google_gemini_tuned_models",
				IDKeys:           []string{"name", "displayName", "deployment_id", "id", "url", "uid"},
				CursorParam:      "pageToken",
				NextCursorKeys:   []string{"nextPageToken"},
				PageSizeParams:   []string{"pageSize"},
				ListKeys:         []string{"tunedModels"},
				Config:           jsonapi.FamilyConfig{ResourceURNKind: "google_gemini_tuned_models"},
				TimestampKeys:    []string{"updateTime", "createTime", "observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"deployment_branch": "branch|ref|git_branch|head_branch", "deployment_commit_sha": "commit_sha|commit|sha|revision|git_sha", "deployment_created_at": "createTime|created_at|created|date_created", "deployment_environment": "environment|env|stage|target", "deployment_id": "name", "deployment_name": "displayName|name", "deployment_status": "state|status|ready", "deployment_updated_at": "updateTime|updated_at|updated|last_modified", "deployment_url": "url|deployment_url|endpoint|domain", "evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "observed_at": "updateTime|observed_at|updated_at|last_seen_at", "resource_id": "name|resource_id|id|metadata.resource_id", "resource_name": "displayName|name|display_name|hostname|metadata.resource_name", "resource_type": "resource_type|type|metadata.resource_type", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "name|event_id|id|metadata.event_id", "tenant_id": "tenant_id|metadata.tenant_id"},
				StaticAttributes: map[string]string{"record_class": "deployment", "resource_type": "tuned_models", "schema": "tuned_models", "source_system": "google_gemini"},
			},
			{
				Name:             familyFiles,
				Path:             "/v1beta/files",
				URNKind:          "google_gemini_files",
				IDKeys:           []string{"name", "displayName", "id", "urn", "resource_urn"},
				CursorParam:      "pageToken",
				NextCursorKeys:   []string{"nextPageToken"},
				PageSizeParams:   []string{"pageSize"},
				ListKeys:         []string{"files"},
				Config:           jsonapi.FamilyConfig{ResourceURNKind: "google_gemini_files"},
				TimestampKeys:    []string{"updateTime", "createTime", "expirationTime", "observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "observed_at": "updateTime|observed_at|updated_at|last_seen_at", "resource_id": "name", "resource_name": "displayName|name", "resource_type": "resource_type|type|kind", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "name|event_id|id|metadata.event_id", "tenant_id": "tenant_id|metadata.tenant_id"},
				StaticAttributes: map[string]string{"record_class": "asset", "resource_type": "files", "schema": "files", "source_system": "google_gemini"},
			},
			{
				Name:             familyCachedContents,
				Path:             "/v1beta/cachedContents",
				URNKind:          "google_gemini_cached_contents",
				IDKeys:           []string{"name", "displayName", "id", "urn", "resource_urn"},
				CursorParam:      "pageToken",
				NextCursorKeys:   []string{"nextPageToken"},
				PageSizeParams:   []string{"pageSize"},
				ListKeys:         []string{"cachedContents"},
				Config:           jsonapi.FamilyConfig{ResourceURNKind: "google_gemini_cached_contents"},
				TimestampKeys:    []string{"updateTime", "createTime", "expireTime", "observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "observed_at": "updateTime|observed_at|updated_at|last_seen_at", "resource_id": "name", "resource_name": "displayName|model|name", "resource_type": "resource_type|type|kind", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "name|event_id|id|metadata.event_id", "tenant_id": "tenant_id|metadata.tenant_id"},
				StaticAttributes: map[string]string{"record_class": "asset", "resource_type": "cached_contents", "schema": "cached_contents", "source_system": "google_gemini"},
			},
			{
				Name:             familyBatchJobs,
				Path:             "/v1beta/batches",
				URNKind:          "google_gemini_batch_jobs",
				IDKeys:           []string{"name", "displayName", "deployment_id", "id", "url", "uid"},
				CursorParam:      "pageToken",
				NextCursorKeys:   []string{"nextPageToken"},
				PageSizeParams:   []string{"pageSize"},
				ListKeys:         []string{"operations"},
				Config:           jsonapi.FamilyConfig{ResourceURNKind: "google_gemini_batch_jobs"},
				TimestampKeys:    []string{"metadata.updateTime", "metadata.createTime", "response.updateTime", "response.createTime", "observed_at", "updated_at", "last_seen_at", "created_at"},
				Attributes:       map[string]string{"deployment_branch": "branch|ref|git_branch|head_branch", "deployment_commit_sha": "commit_sha|commit|sha|revision|git_sha", "deployment_created_at": "metadata.createTime|response.createTime|created_at|created|date_created", "deployment_environment": "environment|env|stage|target", "deployment_id": "name", "deployment_name": "metadata.displayName|response.displayName|displayName|name", "deployment_status": "metadata.state|response.state|state|status|done", "deployment_updated_at": "metadata.updateTime|response.updateTime|updated_at|updated|last_modified", "deployment_url": "url|deployment_url|endpoint|domain", "evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "observed_at": "metadata.updateTime|response.updateTime|observed_at|updated_at|last_seen_at", "resource_id": "name|resource_id|id|metadata.resource_id", "resource_name": "metadata.displayName|response.displayName|displayName|name|display_name|hostname|metadata.resource_name", "resource_type": "resource_type|type|metadata.resource_type", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "name|event_id|id|metadata.event_id", "tenant_id": "tenant_id|metadata.tenant_id"},
				StaticAttributes: map[string]string{"record_class": "deployment", "resource_type": "batch_jobs", "schema": "batch_jobs", "source_system": "google_gemini"},
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
	if firstNonEmpty(sourcecdk.ConfigValue(cfg, "api_key"), sourcecdk.ConfigValue(cfg, "api_token"), sourcecdk.ConfigValue(cfg, "token")) == "" {
		return sourcecdk.Config{}, fmt.Errorf("%w: %s api_key is required", sourcecdk.ErrInvalidConfig, sourceID)
	}
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
