package alation

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
	sourceID               = "alation"
	defaultFamily          = familyUsers
	defaultHealthPath      = "/integration/v2/user/?limit=1&skip=0"
	defaultBaseURLTemplate = "${config.base_url}"
	tokenHeader            = "TOKEN"
	tokenScheme            = ""
	familyUsers            = "users"
	familyGroups           = "groups"
	familyDataSources      = "data_sources"
	familyPolicies         = "policies"
	familyTerms            = "terms"
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
			alationUsersFamily(),
			alationGroupsFamily(),
			alationAssetFamily(familyDataSources, "/integration/v1/datasource/", "alation_data_sources", "data_source", dataSourceAttributes()),
			alationPoliciesFamily(),
			alationAssetFamily(familyTerms, "/integration/v2/term/", "alation_terms", "term", termAttributes()),
		},
	})
	if err != nil {
		return nil, err
	}
	return &Source{inner: inner}, nil
}

func alationUsersFamily() jsonapi.Family {
	return alationOffsetFamily(jsonapi.Family{
		Name:          familyUsers,
		Path:          "/integration/v2/user/",
		URNKind:       "alation_users",
		IDKeys:        []string{"id", "email", "display_name"},
		TimestampKeys: []string{"last_login", "ts_created"},
		Attributes: map[string]string{
			"created_at":      "ts_created",
			"display_name":    "display_name|name|email",
			"email":           "email",
			"last_login_at":   "last_login",
			"login":           "email|username",
			"observed_at":     "last_login|ts_created",
			"primary_email":   "email",
			"resource_id":     "id",
			"resource_name":   "display_name|email",
			"resource_type":   "user",
			"source_event_id": "id",
			"status":          "profile_status|status|is_active",
			"tenant_id":       "tenant_id|metadata.tenant_id",
			"user_id":         "id",
		},
		StaticAttributes: map[string]string{"record_class": "identity_user", "schema": "users", "source_system": "alation"},
	})
}

func alationGroupsFamily() jsonapi.Family {
	return alationOffsetFamily(jsonapi.Family{
		Name:          familyGroups,
		Path:          "/integration/v1/group/",
		URNKind:       "alation_groups",
		IDKeys:        []string{"id", "email", "display_name"},
		TimestampKeys: []string{"ts_created"},
		Attributes: map[string]string{
			"created_at":      "ts_created",
			"display_name":    "display_name|name|email",
			"email":           "email",
			"group_id":        "id",
			"group_name":      "display_name|name|email",
			"observed_at":     "ts_created",
			"resource_id":     "id",
			"resource_name":   "display_name|name|email",
			"resource_type":   "group",
			"source_event_id": "id",
			"tenant_id":       "tenant_id|metadata.tenant_id",
		},
		StaticAttributes: map[string]string{"record_class": "identity_group", "schema": "groups", "source_system": "alation"},
	})
}

func alationAssetFamily(name, path, urnKind, resourceType string, attrs map[string]string) jsonapi.Family {
	attrs["resource_type"] = resourceType
	return alationOffsetFamily(jsonapi.Family{
		Name:       name,
		Path:       path,
		URNKind:    urnKind,
		IDKeys:     []string{"id", "title", "name", "url"},
		Attributes: attrs,
		StaticAttributes: map[string]string{
			"record_class":  "asset",
			"resource_type": resourceType,
			"schema":        name,
			"source_system": "alation",
		},
	})
}

func alationPoliciesFamily() jsonapi.Family {
	return alationOffsetFamily(jsonapi.Family{
		Name:          familyPolicies,
		Path:          "/integration/v1/business_policies/",
		URNKind:       "alation_policies",
		IDKeys:        []string{"id", "title", "name"},
		TimestampKeys: []string{"ts_created", "ts_updated"},
		Attributes: map[string]string{
			"observed_at":        "ts_updated|ts_created",
			"policy_created_at":  "ts_created",
			"policy_description": "description|body",
			"policy_id":          "id",
			"policy_name":        "title|name",
			"policy_status":      "deleted|status",
			"policy_type":        "business_policy",
			"resource_id":        "id",
			"resource_name":      "title|name",
			"resource_type":      "business_policy",
			"resource_urn":       "resource_urn|urn|metadata.resource_urn",
			"source_event_id":    "id",
			"tenant_id":          "tenant_id|metadata.tenant_id",
		},
		StaticAttributes: map[string]string{"record_class": "policy", "schema": "policies", "source_system": "alation"},
	})
}

func alationOffsetFamily(family jsonapi.Family) jsonapi.Family {
	family.CursorParam = "skip"
	family.PageFirstCursor = "0"
	family.PageSizeParams = []string{"limit"}
	family.Config.OffsetCursor = true
	family.Config.DefaultPageSize = 100
	family.Config.ResourceURNKind = family.URNKind
	return family
}

func dataSourceAttributes() map[string]string {
	attrs := assetAttributes()
	attrs["dbtype"] = "dbtype"
	attrs["description"] = "description"
	attrs["is_virtual"] = "is_virtual"
	attrs["resource_name"] = "title|name"
	attrs["source_url"] = "url"
	attrs["uri"] = "uri"
	return attrs
}

func termAttributes() map[string]string {
	attrs := assetAttributes()
	attrs["description"] = "description"
	attrs["glossary_id"] = "glossary_id"
	attrs["resource_name"] = "title|name"
	attrs["term_id"] = "id"
	return attrs
}

func assetAttributes() map[string]string {
	return map[string]string{
		"created_at":      "ts_created|created_at|created",
		"observed_at":     "ts_updated|updated_at|ts_created|created_at",
		"resource_id":     "id",
		"resource_name":   "title|name|display_name|url",
		"resource_type":   "otype|resource_type|type",
		"resource_urn":    "resource_urn|urn|metadata.resource_urn",
		"source_event_id": "id",
		"tenant_id":       "tenant_id|metadata.tenant_id",
		"updated_at":      "ts_updated|updated_at",
		"web_url":         "url",
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
