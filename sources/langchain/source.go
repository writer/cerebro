package langchain

import (
	"context"
	"embed"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/sources/internal/jsonapi"
)

//go:embed catalog.yaml
var catalogFS embed.FS

const sourceID = "langchain"

type Source struct{ inner *jsonapi.Source }

type familyOption func(*jsonapi.Family)

var (
	staticAttributes = map[string]string{"source_product": "langchain", "product": "langsmith"}
	configHeaders    = map[string]string{
		"X-Organization-Id": "organization_id",
		"X-Tenant-Id":       "workspace_id",
	}
)

func New() (*Source, error) {
	spec, err := loadSpec()
	if err != nil {
		return nil, err
	}
	inner, err := jsonapi.New(spec, jsonapi.Options{
		SourceID:               sourceID,
		DefaultBaseURL:         "https://api.smith.langchain.com",
		DefaultFamily:          "workspace",
		RequireTenantID:        true,
		TokenHeader:            "X-API-Key",
		ConfigHeaders:          configHeaders,
		ConfigurableAuthModels: []string{"api_key", "bearer_token"},
		Families:               langChainFamilies(),
	})
	if err != nil {
		return nil, err
	}
	return &Source{inner: inner}, nil
}

func (s *Source) Spec() *cerebrov1.SourceSpec { return s.inner.Spec() }
func (s *Source) Check(ctx context.Context, cfg sourcecdk.Config) error {
	return s.inner.Check(ctx, cfg)
}
func (s *Source) Discover(ctx context.Context, cfg sourcecdk.Config) ([]sourcecdk.URN, error) {
	return s.inner.Discover(ctx, cfg)
}
func (s *Source) Read(ctx context.Context, cfg sourcecdk.Config, cursor *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
	return s.inner.Read(ctx, cfg, cursor)
}

func langChainFamilies() []jsonapi.Family {
	return []jsonapi.Family{
		langChainSingletonFamily("organization", "/api/v1/orgs/current", "langchain_org", map[string]string{
			"organization_id":   "id|organization_id",
			"organization_name": "display_name|name",
			"name":              "display_name|name",
			"plan":              "plan",
			"created_at":        "created_at",
			"updated_at":        "updated_at",
		}, withConfigAttributes(map[string]string{"organization_id": "organization_id"})),
		langChainListFamily("workspace", "/api/v1/workspaces", "langchain_workspace", []string{"id"}, []string{"created_at"}, map[string]string{
			"workspace_id":    "id|tenant_id|workspace_id",
			"organization_id": "organization_id",
			"name":            "display_name|name",
			"tenant_handle":   "tenant_handle",
			"data_plane_url":  "data_plane_url",
			"role_id":         "role_id",
			"role":            "role_name",
			"is_deleted":      "is_deleted",
			"created_at":      "created_at",
		}, withConfigAttributes(map[string]string{"organization_id": "organization_id"}), withQuery(map[string]string{"include_deleted": "include_deleted", "data_plane_id": "data_plane_id"})),
		langChainListFamily("organization_member", "/api/v1/orgs/current/members", "langchain_user", []string{"id", "identity_id", "user_id", "email"}, []string{"created_at", "updated_at"}, memberAttributes(), withConfigAttributes(map[string]string{"organization_id": "organization_id"})),
		langChainListFamily("workspace_member", "/api/v1/workspaces/current/members", "langchain_workspace_member", []string{"id", "identity_id", "user_id", "email"}, []string{"created_at", "updated_at"}, memberAttributes(), withConfigAttributes(map[string]string{"organization_id": "organization_id", "workspace_id": "workspace_id"})),
		langChainListFamily("role", "/api/v1/orgs/current/roles", "langchain_role", []string{"id", "role_id", "display_name", "name"}, []string{"created_at", "updated_at"}, roleAttributes(), withConfigAttributes(map[string]string{"organization_id": "organization_id"})),
		langChainListFamily("api_key", "/api/v1/orgs/current/service-keys", "langchain_api_key", []string{"id", "api_key_id", "key_id"}, []string{"created_at", "updated_at", "expires_at", "last_used_at"}, credentialAttributes(), withConfigAttributes(map[string]string{"organization_id": "organization_id"}), withStaticAttributes(map[string]string{"credential_type": "langchain_service_key"})),
		langChainListFamily("service_account", "/api/v1/service-accounts", "langchain_service_account", []string{"id", "service_account_id"}, []string{"created_at", "updated_at"}, map[string]string{
			"service_account_id": "id|service_account_id",
			"name":               "display_name|name",
			"role":               "role_name|role",
			"status":             "status",
			"created_at":         "created_at",
			"updated_at":         "updated_at",
		}, withConfigAttributes(map[string]string{"organization_id": "organization_id"})),
		langChainListFamily("project", "/api/v1/sessions", "langchain_project", []string{"id", "session_id"}, []string{"start_time", "created_at", "updated_at"}, map[string]string{
			"project_id":      "id|session_id",
			"workspace_id":    "tenant_id|workspace_id",
			"organization_id": "organization_id",
			"name":            "name",
			"description":     "description",
			"start_time":      "start_time",
			"created_at":      "created_at",
			"updated_at":      "updated_at",
		}, withConfigAttributes(map[string]string{"organization_id": "organization_id", "workspace_id": "workspace_id"}), withOffsetCursor(), withQuery(map[string]string{"name": "name", "name_contains": "name_contains", "include_stats": "include_stats", "filter": "filter"})),
		langChainListFamily("run", "/api/v1/runs", "langchain_run", []string{"id", "run_id"}, []string{"start_time", "end_time", "created_at"}, runAttributes(), withConfigAttributes(map[string]string{"organization_id": "organization_id", "workspace_id": "workspace_id"}), withOffsetCursor(), withQuery(map[string]string{"project": "project", "session": "session", "start_time": "start_time", "end_time": "end_time", "run_type": "run_type", "filter": "filter"})),
		langChainListFamily("feedback", "/api/v1/feedback", "langchain_feedback", []string{"id", "feedback_id"}, []string{"created_at", "modified_at", "updated_at"}, map[string]string{
			"feedback_id":     "id|feedback_id",
			"run_id":          "run_id",
			"project_id":      "session_id|project_id",
			"key":             "key",
			"score":           "score",
			"value":           "value",
			"comment":         "comment",
			"correction":      "correction",
			"source_info":     "source_info",
			"feedback_source": "feedback_source.type|feedback_source",
			"created_at":      "created_at",
			"updated_at":      "modified_at|updated_at",
		}, withConfigAttributes(map[string]string{"organization_id": "organization_id", "workspace_id": "workspace_id"}), withOffsetCursor(), withQuery(map[string]string{"run": "run_id", "key": "key", "feedback_source": "feedback_source"})),
		langChainListFamily("dataset", "/api/v1/datasets", "langchain_dataset", []string{"id", "dataset_id", "name"}, []string{"created_at", "updated_at"}, map[string]string{
			"dataset_id":      "id|dataset_id",
			"name":            "name",
			"description":     "description",
			"workspace_id":    "tenant_id|workspace_id",
			"organization_id": "organization_id",
			"created_at":      "created_at",
			"updated_at":      "updated_at",
		}, withConfigAttributes(map[string]string{"organization_id": "organization_id", "workspace_id": "workspace_id"}), withOffsetCursor(), withQuery(map[string]string{"name": "name", "name_contains": "name_contains"})),
		langChainListFamily("usage_limit", "/api/v1/usage-limits", "langchain_usage_limit", []string{"id", "usage_limit_id", "name"}, []string{"created_at", "updated_at"}, map[string]string{
			"usage_limit_id":  "id|usage_limit_id",
			"name":            "name",
			"limit":           "limit|amount",
			"period":          "period",
			"scope_type":      "scope_type|scope.type",
			"workspace_id":    "tenant_id|workspace_id|scope.tenant_id",
			"organization_id": "organization_id",
			"created_at":      "created_at",
			"updated_at":      "updated_at",
		}, withConfigAttributes(map[string]string{"organization_id": "organization_id", "workspace_id": "workspace_id"})),
		langChainListFamily("audit_log", "/api/v1/audit-logs", "langchain_audit_log", []string{"id", "audit_log_id"}, []string{"created_at", "timestamp", "time"}, auditAttributes(), withConfigAttributes(map[string]string{"organization_id": "organization_id", "workspace_id": "workspace_id"}), withOffsetCursor(), withQuery(map[string]string{"start_time": "start_time", "end_time": "end_time", "event_type": "event_type"})),
	}
}

func langChainListFamily(name string, path string, urnKind string, idKeys []string, timestampKeys []string, attrs map[string]string, opts ...familyOption) jsonapi.Family {
	family := jsonapi.Family{
		Name:             name,
		Path:             path,
		URNKind:          urnKind,
		IDKeys:           idKeys,
		TimestampKeys:    timestampKeys,
		Attributes:       attrs,
		StaticAttributes: staticAttributes,
		PageSizeParams:   []string{"limit"},
	}
	for _, opt := range opts {
		opt(&family)
	}
	return family
}

func langChainSingletonFamily(name string, path string, urnKind string, attrs map[string]string, opts ...familyOption) jsonapi.Family {
	return langChainListFamily(name, path, urnKind, []string{"id", "organization_id"}, nil, attrs, append(opts, func(f *jsonapi.Family) {
		f.Singleton = true
		f.DisablePageSize = true
		f.CursorParam = ""
		f.NextCursorKeys = nil
		f.HasMoreKey = ""
	})...)
}

func memberAttributes() map[string]string {
	return map[string]string{
		"user_id":         "id|identity_id|user_id|user.id|email",
		"identity_id":     "identity_id|id",
		"email":           "email|user.email",
		"name":            "full_name|name|display_name|user.name",
		"role":            "role_name|role.name|role|display_name",
		"role_id":         "role_id|role.id",
		"status":          "status",
		"workspace_id":    "tenant_id|workspace_id",
		"organization_id": "organization_id",
		"created_at":      "created_at",
		"updated_at":      "updated_at",
	}
}

func roleAttributes() map[string]string {
	return map[string]string{
		"role_id":         "id|role_id|name|display_name",
		"name":            "display_name|name",
		"role":            "display_name|name",
		"scope":           "access_scope|scope",
		"description":     "description",
		"permissions":     "permissions",
		"organization_id": "organization_id",
		"created_at":      "created_at",
		"updated_at":      "updated_at",
	}
}

func credentialAttributes() map[string]string {
	return map[string]string{ // #nosec G101 -- provider API field names only, not credential material.
		"api_key_id":      "id|api_key_id|key_id",
		"credential_id":   "id|api_key_id|key_id",
		"name":            "name|display_name",
		"status":          "status",
		"role":            "role_name|role",
		"role_id":         "role_id",
		"owner_id":        "created_by.id|owner.id|owner_id",
		"owner_user_id":   "created_by.id|owner.user_id|user_id",
		"owner_name":      "created_by.name|owner.name",
		"owner_type":      "owner.type|owner_type",
		"workspace_id":    "tenant_id|workspace_id",
		"organization_id": "organization_id",
		"created_at":      "created_at",
		"updated_at":      "updated_at",
		"expires_at":      "expires_at",
		"last_used_at":    "last_used_at",
	}
}

func runAttributes() map[string]string {
	return map[string]string{
		"run_id":          "id|run_id",
		"project_id":      "session_id|project_id",
		"workspace_id":    "tenant_id|workspace_id",
		"organization_id": "organization_id",
		"name":            "name",
		"run_type":        "run_type",
		"status":          "status",
		"error":           "error",
		"user_id":         "user_id|metadata.user_id",
		"model":           "extra.invocation_params.model|model",
		"input_tokens":    "prompt_tokens|inputs.prompt_tokens|usage_metadata.input_tokens",
		"output_tokens":   "completion_tokens|outputs.completion_tokens|usage_metadata.output_tokens",
		"total_tokens":    "total_tokens|usage_metadata.total_tokens",
		"start_time":      "start_time",
		"end_time":        "end_time",
		"created_at":      "created_at",
	}
}

func auditAttributes() map[string]string {
	return map[string]string{
		"audit_log_id":     "id|audit_log_id",
		"event_type":       "event_type|action|event",
		"activity_type":    "event_type|action|event",
		"actor_id":         "actor.id|actor_id|user_id",
		"actor_user_id":    "actor.user_id|actor.id|user_id",
		"actor_email":      "actor.email|email",
		"actor_name":       "actor.name|name",
		"actor_type":       "actor.type|actor_type",
		"resource_id":      "resource.id|resource_id|target_id",
		"resource_type":    "resource.type|resource_type|target_type",
		"resource_name":    "resource.name|resource_name|target_name",
		"project_id":       "session_id|project_id",
		"workspace_id":     "tenant_id|workspace_id",
		"organization_id":  "organization_id",
		"actor_ip_address": "ip_address|actor.ip_address",
		"created_at":       "created_at|timestamp|time",
	}
}

func withConfigAttributes(attrs map[string]string) familyOption {
	return func(f *jsonapi.Family) {
		f.Config.ConfigAttributes = attrs
	}
}

func withStaticAttributes(extra map[string]string) familyOption {
	return func(f *jsonapi.Family) {
		jsonapi.MergeStaticAttributes(f, extra)
	}
}

func withOffsetCursor() familyOption {
	return func(f *jsonapi.Family) {
		f.CursorParam = "offset"
		f.NextCursorKeys = []string{"next_offset", "nextOffset"}
	}
}

func withQuery(query map[string]string) familyOption {
	return func(f *jsonapi.Family) {
		f.Config.ConfigQuery = query
	}
}

func loadSpec() (*cerebrov1.SourceSpec, error) {
	return sourcecdk.LoadSpecFromFS(catalogFS, "catalog.yaml")
}
