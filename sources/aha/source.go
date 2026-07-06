package aha

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
	sourceID               = "aha"
	defaultFamily          = familyUsers
	defaultHealthPath      = "/me"
	defaultBaseURLTemplate = "${config.base_url}/api/v1"
	tokenHeader            = ""
	tokenScheme            = "Bearer"
	familyUsers            = "users"
	familyProducts         = "products"
	familyFeatures         = "features"
	familyReleases         = "releases"
	familyAuditEvents      = "audit_events"
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
		AuthModel:       "bearer_token",
		TokenHeader:     tokenHeader,
		TokenScheme:     tokenScheme,
		Families: []jsonapi.Family{
			ahaListFamily(familyUsers, "/users", "aha_users", []string{"id", "email", "name"}, []string{"users"}, userAttributes(), map[string]string{"record_class": "identity_user", "schema": "users", "source_system": "aha"}),
			ahaAssetFamily(familyProducts, "/products", "aha_products", []string{"id", "reference_prefix", "name"}, []string{"products"}, "product", productAttributes()),
			ahaAssetFamily(familyFeatures, "/features", "aha_features", []string{"id", "reference_num", "name"}, []string{"features"}, "feature", featureAttributes()),
			ahaReleaseFamily(),
			ahaListFamily(familyAuditEvents, "/audits", "aha_audit_events", []string{"id", "auditable_id", "created_at"}, []string{"audits"}, auditAttributes(), map[string]string{"record_class": "audit_event", "schema": "audit_events", "source_system": "aha"}),
		},
	})
	if err != nil {
		return nil, err
	}
	return &Source{inner: inner}, nil
}

func ahaListFamily(name, path, urnKind string, idKeys, listKeys []string, attrs map[string]string, static map[string]string) jsonapi.Family {
	return jsonapi.Family{
		Name:             name,
		Path:             path,
		URNKind:          urnKind,
		IDKeys:           idKeys,
		CursorParam:      "page",
		PageFirstCursor:  "1",
		PageSizeParams:   []string{"per_page"},
		ListKeys:         listKeys,
		TimestampKeys:    []string{"updated_at", "created_at", "last_active_at", "last_login_at"},
		Attributes:       attrs,
		StaticAttributes: static,
	}
}

func ahaAssetFamily(name, path, urnKind string, idKeys, listKeys []string, resourceType string, attrs map[string]string) jsonapi.Family {
	static := map[string]string{"record_class": "asset", "resource_type": resourceType, "schema": name, "source_system": "aha"}
	family := ahaListFamily(name, path, urnKind, idKeys, listKeys, attrs, static)
	family.Config.ResourceURNKind = urnKind
	return family
}

func ahaReleaseFamily() jsonapi.Family {
	attrs := releaseAttributes()
	family := ahaAssetFamily(familyReleases, "/products/{product_id}/releases", "aha_releases", []string{"id", "reference_num", "name"}, []string{"releases"}, "release", attrs)
	family.PathParams = []string{"product_id"}
	return family
}

func userAttributes() map[string]string {
	return map[string]string{
		"created_at":      "created_at",
		"display_name":    "name",
		"email":           "email",
		"last_login_at":   "last_login_at|last_active_at",
		"login":           "email|name",
		"observed_at":     "updated_at|created_at|last_active_at",
		"primary_email":   "email",
		"resource_id":     "id",
		"resource_name":   "name",
		"resource_type":   "user",
		"source_event_id": "id",
		"status":          "disabled|enabled|status",
		"tenant_id":       "tenant_id|metadata.tenant_id",
		"user_id":         "id",
	}
}

func productAttributes() map[string]string {
	attrs := assetAttributes()
	attrs["product_id"] = "id"
	attrs["product_key"] = "reference_prefix"
	attrs["workflow_status"] = "workflow_status.name|workflow_status"
	return attrs
}

func featureAttributes() map[string]string {
	attrs := assetAttributes()
	attrs["feature_id"] = "id"
	attrs["reference_num"] = "reference_num"
	attrs["workflow_status"] = "workflow_status.name|workflow_status"
	attrs["product_id"] = "product.id|product_id"
	attrs["release_id"] = "release.id|release_id"
	return attrs
}

func releaseAttributes() map[string]string {
	attrs := assetAttributes()
	attrs["release_id"] = "id"
	attrs["reference_num"] = "reference_num"
	attrs["release_date"] = "release_date|released_on"
	attrs["workflow_status"] = "workflow_status.name|workflow_status"
	attrs["product_id"] = "product.id|product_id"
	return attrs
}

func assetAttributes() map[string]string {
	return map[string]string{
		"created_at":      "created_at",
		"description":     "description.body|description|body",
		"id":              "id",
		"name":            "name|reference_num",
		"observed_at":     "updated_at|created_at",
		"resource_id":     "id",
		"resource_name":   "name|reference_num",
		"source_event_id": "id",
		"tenant_id":       "tenant_id|metadata.tenant_id",
	}
}

func auditAttributes() map[string]string {
	return map[string]string{
		"actor_email":     "user.email|actor.email",
		"actor_id":        "user.id|user_id|actor_id",
		"actor_name":      "user.name|actor.name",
		"event_type":      "action|audit_action|event_type",
		"id":              "id",
		"observed_at":     "created_at",
		"resource_id":     "auditable_id|associated_id|resource_id",
		"resource_name":   "auditable_name|associated_name|resource_name",
		"resource_type":   "auditable_type|associated_type|resource_type",
		"source_event_id": "id",
		"tenant_id":       "tenant_id|metadata.tenant_id",
	}
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
