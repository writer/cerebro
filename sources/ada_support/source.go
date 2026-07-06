package ada_support

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
	sourceID                   = "ada_support"
	defaultFamily              = familyEndUsers
	defaultHealthPath          = "/v2/end-users/"
	defaultBaseURLTemplate     = "${config.base_url}"
	tokenHeader                = ""
	tokenScheme                = "Bearer"
	familyEndUsers             = "end_users"
	familyPlatformIntegrations = "platform_integrations"
	familyConversations        = "conversations"
	familyKnowledgeArticles    = "knowledge_articles"
	familyAuditEvents          = "audit_events"
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
			{
				Name:           familyEndUsers,
				Path:           "/v2/end-users/",
				URNKind:        "ada_support_end_users",
				IDKeys:         []string{"end_user_id", "id", "external_id", "profile.email"},
				CursorParam:    "cursor",
				NextCursorKeys: []string{"meta.next_page_url", "next_page_url"},
				PageSizeParams: []string{"limit"},
				ListKeys:       []string{"data"},
				TimestampKeys:  []string{"updated_at", "created_at"},
				Attributes: map[string]string{
					"created_at": "created_at", "display_name": "profile.display_name|profile.first_name|external_id|end_user_id", "email": "profile.email", "external_id": "external_id", "observed_at": "updated_at|created_at", "primary_email": "profile.email", "resource_id": "end_user_id|id|external_id", "resource_name": "profile.display_name|external_id|end_user_id", "resource_type": "end_user", "resource_urn": "resource_urn", "source_event_id": "end_user_id|id|external_id", "status": "status", "tenant_id": "tenant_id|metadata.tenant_id", "user_id": "end_user_id|id|external_id",
				},
				StaticAttributes: map[string]string{"record_class": "identity_user", "resource_type": "end_user", "schema": "end_users", "source_system": "ada_support"},
			},
			{
				Name:           familyPlatformIntegrations,
				Path:           "/v2/platform-integrations/",
				URNKind:        "ada_support_platform_integrations",
				IDKeys:         []string{"id", "name"},
				CursorParam:    "cursor",
				NextCursorKeys: []string{"meta.next_page_url", "next_page_url"},
				PageSizeParams: []string{"limit"},
				ListKeys:       []string{"data"},
				TimestampKeys:  []string{"updated", "created"},
				Attributes: map[string]string{
					"description": "description", "id": "id", "name": "name", "observed_at": "updated|created", "resource_id": "id", "resource_name": "name", "resource_urn": "resource_urn", "source_event_id": "id", "status": "status", "tenant_id": "tenant_id|metadata.tenant_id",
				},
				StaticAttributes: map[string]string{"record_class": "asset", "resource_type": "platform_integration", "schema": "platform_integrations", "source_system": "ada_support"},
			},
			{
				Name:           familyConversations,
				Path:           "/v2/export/conversations",
				URNKind:        "ada_support_conversations",
				IDKeys:         []string{"_id", "id", "conversation_id"},
				CursorParam:    "cursor",
				NextCursorKeys: []string{"meta.next_page_uri", "next_page_uri"},
				PageSizeParams: []string{"page_size"},
				ListKeys:       []string{"items"},
				TimestampKeys:  []string{"record_last_updated", "date_updated", "date_created"},
				Config:         jsonapi.FamilyConfig{ConfigQuery: map[string]string{"created_since": "created_since", "created_to": "created_to", "updated_since": "updated_since", "updated_to": "updated_to"}},
				Attributes: map[string]string{
					"id": "_id|id|conversation_id", "name": "inquiry_summary|generated_topic_label|_id", "observed_at": "record_last_updated|date_updated|date_created", "resource_id": "_id|id|conversation_id", "resource_name": "inquiry_summary|generated_topic_label|_id", "resource_urn": "resource_urn", "source_event_id": "_id|id|conversation_id", "tenant_id": "tenant_id|metadata.tenant_id",
				},
				StaticAttributes: map[string]string{"record_class": "asset", "resource_type": "conversation", "schema": "conversations", "source_system": "ada_support"},
			},
			{
				Name:           familyKnowledgeArticles,
				Path:           "/v2/knowledge/articles/",
				URNKind:        "ada_support_knowledge_articles",
				IDKeys:         []string{"id", "name", "title"},
				CursorParam:    "cursor",
				NextCursorKeys: []string{"meta.next_page_url", "next_page_url"},
				PageSizeParams: []string{"limit"},
				ListKeys:       []string{"data"},
				TimestampKeys:  []string{"updated_at", "created_at"},
				Attributes: map[string]string{
					"observed_at": "updated_at|created_at", "policy_created_at": "created_at", "policy_description": "description|content|body", "policy_id": "id", "policy_name": "name|title", "policy_status": "enabled|status", "resource_id": "id", "resource_name": "name|title", "resource_urn": "resource_urn", "source_event_id": "id", "tenant_id": "tenant_id|metadata.tenant_id",
				},
				StaticAttributes: map[string]string{"policy_type": "knowledge_article", "record_class": "policy", "resource_type": "knowledge_article", "schema": "knowledge_articles", "source_system": "ada_support"},
			},
			{
				Name:           familyAuditEvents,
				Path:           "/v2/analytics/audit-log/events/",
				URNKind:        "ada_support_audit_events",
				IDKeys:         []string{"id"},
				CursorParam:    "cursor",
				NextCursorKeys: []string{"meta.next_page_url", "next_page_url"},
				PageSizeParams: []string{"limit"},
				ListKeys:       []string{"data"},
				TimestampKeys:  []string{"timestamp"},
				Config:         jsonapi.FamilyConfig{ConfigQuery: map[string]string{"start_date": "start_date", "end_date": "end_date"}},
				Attributes: map[string]string{
					"actor_email": "actor_email", "actor_id": "actor_user_id|actor_email|api_key_name", "actor_name": "actor_name", "event_type": "activity|entity_type", "id": "id", "observed_at": "timestamp", "resource_id": "entity_id", "resource_name": "entity_name", "resource_type": "entity_type", "resource_urn": "resource_urn", "source_event_id": "id", "tenant_id": "tenant_id|metadata.tenant_id",
				},
				StaticAttributes: map[string]string{"record_class": "audit_event", "schema": "audit_events", "source_system": "ada_support"},
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
