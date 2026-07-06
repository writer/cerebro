package akeyless

import (
	"context"
	"embed"
	"fmt"
	"net/http"
	"strings"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/sources/internal/jsonapi"
)

//go:embed catalog.yaml
var catalogFS embed.FS

const (
	sourceID               = "akeyless"
	defaultFamily          = familyItems
	defaultBaseURLTemplate = "https://api.akeyless.io"
	familyItems            = "items"
	familyAuthMethods      = "auth_methods"
	familyRoles            = "roles"
	familyAnalytics        = "analytics"
)

var templateKeys = []string{"api_token"}

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
		AuthModel:       "none",
		Families: []jsonapi.Family{
			{
				Name:             familyItems,
				Path:             "/list-items",
				URNKind:          "akeyless_items",
				IDKeys:           []string{"item_id", "uid", "name", "item_name"},
				CursorParam:      "pagination-token",
				NextCursorKeys:   []string{"next_page"},
				ListKeys:         []string{"items"},
				TimestampKeys:    []string{"modification_date", "creation_date", "access_date", "observed_at", "updated_at"},
				DisablePageSize:  true,
				Attributes:       map[string]string{"evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "observed_at": "observed_at|updated_at|last_seen_at|modification_date|creation_date", "resource_id": "item_id|uid|id|name", "resource_name": "item_name|name|display_name|hostname", "resource_type": "item_type|type", "resource_urn": "resource_urn|urn|metadata.resource_urn", "secret_created_at": "creation_date|created_at|created|date_created", "secret_id": "item_id|uid|id|name", "secret_last_rotated_at": "secret_last_rotated_at|last_rotated_at|last_rotated|rotated_at", "secret_name": "item_name|name|display_name|label|title", "secret_rotation_enabled": "auto_rotate|rotation_enabled|secret_rotation_enabled", "secret_status": "item_state|secret_status|status|state", "secret_type": "item_type|type|kind", "source_event_id": "item_id|uid|id|name", "tenant_id": "tenant_id|metadata.tenant_id"},
				StaticAttributes: map[string]string{"record_class": "secret", "schema": "items", "source_system": "akeyless"},
				Config:           akeylessBodyConfig(),
			},
			{
				Name:             familyAuthMethods,
				Path:             "/list-auth-methods",
				URNKind:          "akeyless_auth_methods",
				IDKeys:           []string{"auth_method_id", "auth_method_access_id", "auth_method_name"},
				CursorParam:      "pagination-token",
				NextCursorKeys:   []string{"next_page"},
				ListKeys:         []string{"auth_methods"},
				TimestampKeys:    []string{"modification_date", "creation_date", "access_date", "observed_at", "updated_at"},
				DisablePageSize:  true,
				Attributes:       map[string]string{"evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "observed_at": "observed_at|updated_at|last_seen_at|modification_date|creation_date", "resource_id": "auth_method_id|auth_method_access_id|id", "resource_name": "auth_method_name|name|display_name", "resource_type": "auth_method_type|type|access_type", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "auth_method_id|auth_method_access_id|id", "tenant_id": "tenant_id|metadata.tenant_id"},
				StaticAttributes: map[string]string{"record_class": "asset", "schema": "auth_methods", "source_system": "akeyless"},
				Config:           akeylessBodyConfig(),
			},
			{
				Name:             familyRoles,
				Path:             "/list-roles",
				URNKind:          "akeyless_roles",
				IDKeys:           []string{"role_id", "role_name", "id"},
				CursorParam:      "pagination-token",
				NextCursorKeys:   []string{"next_page"},
				ListKeys:         []string{"roles"},
				TimestampKeys:    []string{"modification_date", "creation_date", "access_date", "observed_at", "updated_at"},
				DisablePageSize:  true,
				Attributes:       map[string]string{"description": "comment|description|summary", "domain": "domain|tenant_domain|organization_domain", "evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "group_email": "group_email|email", "group_id": "role_id|id", "group_name": "role_name|name|display_name", "observed_at": "observed_at|updated_at|last_seen_at|modification_date|creation_date", "resource_id": "role_id|id", "resource_name": "role_name|name|display_name", "resource_type": "resource_type|type", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "role_id|id", "tenant_id": "tenant_id|metadata.tenant_id"},
				StaticAttributes: map[string]string{"record_class": "identity_group", "schema": "roles", "source_system": "akeyless"},
				Config:           akeylessBodyConfig(),
			},
			{
				Name:             familyAnalytics,
				Path:             "/get-analytics-data",
				URNKind:          "akeyless_analytics",
				IDKeys:           []string{"date_updated", "id"},
				TimestampKeys:    []string{"observed_at", "updated_at"},
				Attributes:       map[string]string{"evidence_cas_commit_id": "evidence_cas.commit_id|evidence_cas_commit_id|commit_id", "evidence_cas_digest": "evidence_cas.digest|evidence_cas_digest|digest", "evidence_cas_merkle_root": "evidence_cas.merkle_root|evidence_cas_merkle_root|merkle_root", "evidence_cas_ref_type": "evidence_cas.ref_type|evidence_cas_ref_type|ref_type", "evidence_cas_uri": "evidence_cas.uri|evidence_cas_uri|uri", "observed_at": "observed_at|updated_at|date_updated", "resource_id": "date_updated|id", "resource_name": "name|report_name", "resource_type": "resource_type|type", "resource_urn": "resource_urn|urn|metadata.resource_urn", "source_event_id": "date_updated|id", "tenant_id": "tenant_id|metadata.tenant_id", "total_clients": "usage_reports.*.total_clients|total_clients", "total_secrets": "usage_reports.*.total_secrets|total_secrets"},
				StaticAttributes: map[string]string{"record_class": "analytics_report", "resource_type": "akeyless_analytics", "schema": "analytics", "source_system": "akeyless"},
				Singleton:        true,
				Config:           akeylessBodyConfig(),
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

func (s *Source) runtimeConfig(ctx context.Context, cfg sourcecdk.Config) (sourcecdk.Config, error) {
	_ = ctx
	if strings.TrimSpace(sourcecdk.ConfigValue(cfg, "api_token")) == "" {
		return sourcecdk.Config{}, fmt.Errorf("%w: %s api_token is required", sourcecdk.ErrInvalidConfig, sourceID)
	}
	return sourcecdk.ResolveBaseURLConfig(sourceID, defaultBaseURLTemplate, cfg, templateKeys)
}

func akeylessBodyConfig() jsonapi.FamilyConfig {
	return jsonapi.FamilyConfig{
		Method: http.MethodPost,
		JSONBody: jsonapi.JSONBodyConfig{
			Config:      map[string]string{"token": "api_token"},
			CursorParam: "pagination-token",
			SendEmpty:   true,
		},
	}
}

func loadSpec() (*cerebrov1.SourceSpec, error) {
	return sourcecdk.LoadSpecFromFS(catalogFS, "catalog.yaml")
}

func (s *Source) allowLoopbackForTest() {
	if s != nil && s.inner != nil {
		s.inner.AllowLoopbackBaseURL = true
		s.allowLoopback = true
	}
}
