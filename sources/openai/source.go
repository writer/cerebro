package openai

import (
	"context"
	"embed"
	"fmt"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/sources/internal/jsonapi"
)

//go:embed catalog.yaml
var catalogFS embed.FS

const sourceID = "openai"

type Source struct{ inner *jsonapi.Source }

type familyOption func(*jsonapi.Family)

var (
	staticAttributes = map[string]string{"source_product": "openai"}
	usageQuery       = map[string]string{
		"api_key_ids":  "api_key_ids",
		"batch":        "batch",
		"bucket_width": "bucket_width",
		"end_time":     "end_time",
		"group_by":     "group_by",
		"models":       "models",
		"project_ids":  "project_ids",
		"start_time":   "start_time",
		"user_ids":     "user_ids",
	}
)

func New() (*Source, error) {
	spec, err := loadSpec()
	if err != nil {
		return nil, err
	}
	inner, err := jsonapi.New(spec, jsonapi.Options{
		SourceID:        sourceID,
		DefaultBaseURL:  "https://api.openai.com/v1",
		DefaultFamily:   "user",
		RequireTenantID: true,
		TokenScheme:     "Bearer",
		Families:        openAIFamilies(),
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

func openAIFamilies() []jsonapi.Family {
	return []jsonapi.Family{
		openAIListFamily("user", "/organization/users", "openai_user", []string{"id"}, []string{"added_at"}, map[string]string{"user_id": "id", "name": "name", "email": "email", "role": "role", "status": "status", "added_at": "added_at"}),
		openAIListFamily("project", "/organization/projects", "openai_project", []string{"id"}, []string{"created_at"}, map[string]string{"project_id": "id", "name": "name", "status": "status", "created_at": "created_at", "archived_at": "archived_at", "external_key_id": "external_key_id"}),
		openAIListFamily("service_account", "/organization/projects/default/service_accounts", "openai_service_account", []string{"id"}, []string{"created_at"}, map[string]string{"service_account_id": "id", "project_id": "project_id", "name": "name", "role": "role", "created_at": "created_at"}),
		openAIListFamily("api_key", "/organization/projects/default/api_keys", "openai_api_key", []string{"id"}, []string{"created_at", "last_used_at"}, map[string]string{"api_key_id": "id", "project_id": "project_id", "name": "name", "owner_user_id": "owner.user.id", "owner_service_account_id": "owner.service_account.id", "owner_type": "owner.type", "status": "status", "created_at": "created_at", "last_used_at": "last_used_at"}),
		openAIListFamily("admin_api_key", "/organization/admin_api_keys", "openai_admin_api_key", []string{"id"}, []string{"created_at", "last_used_at"}, map[string]string{"api_key_id": "id", "name": "name", "owner_user_id": "owner.user.id", "owner_service_account_id": "owner.service_account.id", "owner_type": "owner.type", "status": "status", "created_at": "created_at", "last_used_at": "last_used_at"}, withStaticAttributes(map[string]string{"key_class": "admin", "privileged": "true"})),
		openAIListFamily("audit_log", "/organization/audit_logs", "openai_audit_log", []string{"id"}, []string{"effective_at", "created_at"}, openAIAuditAttributes(), withQuery(map[string]string{"actor_emails": "actor_emails", "actor_ids": "actor_ids", "effective_at[gt]": "effective_at_gt", "effective_at[gte]": "effective_at_gte", "effective_at[lt]": "effective_at_lt", "effective_at[lte]": "effective_at_lte", "event_types": "event_types", "project_ids": "project_ids", "resource_ids": "resource_ids", "tenant_only": "tenant_only"})),
		openAIListFamily("invite", "/organization/invites", "openai_invite", []string{"id"}, []string{"created_at"}, map[string]string{"invite_id": "id", "email": "email", "role": "role", "status": "status", "projects": "projects", "created_at": "created_at", "accepted_at": "accepted_at", "expires_at": "expires_at"}),
		openAIListFamily("role", "/organization/roles", "openai_role", []string{"id"}, []string{"created_at", "updated_at"}, roleAttributes()),
		openAIListFamily("user_role", "/organization/users/{user_id}/roles", "openai_user_role", []string{"id"}, []string{"created_at", "updated_at"}, roleAttributes(), withPathParams("user_id")),
		openAIListFamily("group", "/organization/groups", "openai_group", []string{"id"}, []string{"created_at", "updated_at"}, map[string]string{"group_id": "id", "name": "name", "created_at": "created_at", "updated_at": "updated_at"}),
		openAIListFamily("group_user", "/organization/groups/{group_id}/users", "openai_group_user", []string{"id", "user_id"}, []string{"added_at", "created_at"}, map[string]string{"group_id": "group_id", "user_id": "id|user_id", "email": "email", "name": "name", "role": "role", "added_at": "added_at"}, withPathParams("group_id")),
		openAIListFamily("group_role", "/organization/groups/{group_id}/roles", "openai_group_role", []string{"id"}, []string{"created_at", "updated_at"}, roleAttributes(), withPathParams("group_id")),
		openAISingletonFamily("data_retention", "/organization/data_retention", "openai_data_retention", map[string]string{"retention_type": "type", "object": "object"}),
		openAIListFamily("spend_alert", "/organization/spend_alerts", "openai_spend_alert", []string{"id"}, []string{"created_at", "updated_at"}, map[string]string{"spend_alert_id": "id", "name": "name", "status": "status", "threshold": "threshold", "threshold_amount": "threshold_amount", "created_at": "created_at", "updated_at": "updated_at"}),
		openAIListFamily("certificate", "/organization/certificates", "openai_certificate", []string{"id"}, []string{"created_at", "certificate_details.expires_at"}, map[string]string{"certificate_id": "id", "name": "name", "active": "active", "created_at": "created_at", "valid_at": "certificate_details.valid_at", "expires_at": "certificate_details.expires_at"}),
		openAIUsageFamily("usage_audio_speech", "/organization/usage/audio_speeches"),
		openAIUsageFamily("usage_audio_transcription", "/organization/usage/audio_transcriptions"),
		openAIUsageFamily("usage_code_interpreter_session", "/organization/usage/code_interpreter_sessions"),
		openAIUsageFamily("usage_completion", "/organization/usage/completions"),
		openAIUsageFamily("usage_embedding", "/organization/usage/embeddings"),
		openAIUsageFamily("usage_image", "/organization/usage/images"),
		openAIUsageFamily("usage_moderation", "/organization/usage/moderations"),
		openAIUsageFamily("usage_vector_store", "/organization/usage/vector_stores"),
		openAIUsageFamily("usage_file_search_call", "/organization/usage/file_search_calls"),
		openAIUsageFamily("usage_web_search_call", "/organization/usage/web_search_calls"),
		openAIUsageFamily("cost", "/organization/costs"),
		openAIListFamily("project_user", "/organization/projects/{project_id}/users", "openai_project_user", []string{"id", "user_id"}, []string{"added_at"}, map[string]string{"project_id": "project_id", "user_id": "id|user_id", "email": "email", "name": "name", "role": "role", "added_at": "added_at"}, withPathParams("project_id")),
		openAIListFamily("project_user_role", "/projects/{project_id}/users/{user_id}/roles", "openai_project_user_role", []string{"id"}, []string{"created_at", "updated_at"}, roleAttributes(), withPathParams("project_id", "user_id"), withCursor("after", "next", "has_more")),
		openAIListFamily("project_service_account", "/organization/projects/{project_id}/service_accounts", "openai_project_service_account", []string{"id"}, []string{"created_at"}, map[string]string{"project_id": "project_id", "service_account_id": "id", "name": "name", "role": "role", "created_at": "created_at"}, withPathParams("project_id")),
		openAIListFamily("project_api_key", "/organization/projects/{project_id}/api_keys", "openai_project_api_key", []string{"id"}, []string{"created_at", "last_used_at"}, map[string]string{"project_id": "project_id", "api_key_id": "id", "name": "name", "owner_user_id": "owner.user.id", "owner_service_account_id": "owner.service_account.id", "owner_type": "owner.type", "status": "status", "created_at": "created_at", "last_used_at": "last_used_at"}, withPathParams("project_id")),
		openAIListFamily("project_rate_limit", "/organization/projects/{project_id}/rate_limits", "openai_project_rate_limit", []string{"id", "model"}, []string{"updated_at", "created_at"}, projectRateLimitAttributes(), withPathParams("project_id")),
		openAISingletonFamily("project_model_permission", "/organization/projects/{project_id}/model_permissions", "openai_project_model_permission", map[string]string{"project_id": "project_id", "mode": "mode", "model_ids": "model_ids"}, withPathParams("project_id")),
		openAISingletonFamily("project_hosted_tool_permission", "/organization/projects/{project_id}/hosted_tool_permissions", "openai_project_hosted_tool_permission", map[string]string{"project_id": "project_id", "code_interpreter_enabled": "code_interpreter.enabled", "file_search_enabled": "file_search.enabled", "image_generation_enabled": "image_generation.enabled", "mcp_enabled": "mcp.enabled", "web_search_enabled": "web_search.enabled"}, withPathParams("project_id")),
		openAIListFamily("project_group", "/organization/projects/{project_id}/groups", "openai_project_group", []string{"id"}, []string{"created_at", "updated_at"}, map[string]string{"project_id": "project_id", "group_id": "id", "name": "name", "created_at": "created_at", "updated_at": "updated_at"}, withPathParams("project_id")),
		openAIListFamily("project_group_role", "/organization/projects/{project_id}/groups/{group_id}/roles", "openai_project_group_role", []string{"id"}, []string{"created_at", "updated_at"}, roleAttributes(), withPathParams("project_id", "group_id")),
		openAIListFamily("project_role", "/projects/{project_id}/roles", "openai_project_role", []string{"id"}, []string{"created_at", "updated_at"}, roleAttributes(), withPathParams("project_id")),
		openAISingletonFamily("project_data_retention", "/organization/projects/{project_id}/data_retention", "openai_project_data_retention", map[string]string{"project_id": "project_id", "retention_type": "type", "object": "object"}, withPathParams("project_id")),
		openAIListFamily("project_spend_alert", "/organization/projects/{project_id}/spend_alerts", "openai_project_spend_alert", []string{"id"}, []string{"created_at", "updated_at"}, map[string]string{"project_id": "project_id", "spend_alert_id": "id", "name": "name", "status": "status", "threshold": "threshold", "threshold_amount": "threshold_amount", "created_at": "created_at", "updated_at": "updated_at"}, withPathParams("project_id")),
		openAIListFamily("project_certificate", "/organization/projects/{project_id}/certificates", "openai_project_certificate", []string{"id"}, []string{"created_at", "certificate_details.expires_at"}, map[string]string{"project_id": "project_id", "certificate_id": "id", "name": "name", "active": "active", "created_at": "created_at", "valid_at": "certificate_details.valid_at", "expires_at": "certificate_details.expires_at"}, withPathParams("project_id")),
	}
}

func openAIListFamily(name string, path string, urnKind string, idKeys []string, timestampKeys []string, attrs map[string]string, opts ...familyOption) jsonapi.Family {
	family := jsonapi.Family{
		Name:             name,
		Path:             path,
		CursorParam:      "after",
		NextCursorKeys:   []string{"next", "last_id"},
		HasMoreKey:       "has_more",
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

func openAISingletonFamily(name string, path string, urnKind string, attrs map[string]string, opts ...familyOption) jsonapi.Family {
	return openAIListFamily(name, path, urnKind, []string{"id"}, nil, attrs, append(opts, func(f *jsonapi.Family) {
		f.Singleton = true
		f.DisablePageSize = true
		f.CursorParam = ""
		f.NextCursorKeys = nil
		f.HasMoreKey = ""
	})...)
}

func openAIUsageFamily(name string, path string) jsonapi.Family {
	attrs := map[string]string{
		"start_time":          "start_time",
		"end_time":            "end_time",
		"result_count":        "results",
		"input_tokens":        "input_tokens",
		"output_tokens":       "output_tokens",
		"num_model_requests":  "num_model_requests",
		"project_id":          "project_id",
		"user_id":             "user_id",
		"api_key_id":          "api_key_id",
		"model":               "model",
		"line_item":           "line_item",
		"amount_value":        "amount.value|amount",
		"amount_currency":     "amount.currency",
		"organization_object": "object",
	}
	return openAIListFamily(name, path, "openai_"+name, []string{"id"}, []string{"start_time", "end_time"}, attrs, withCursor("page", "next_page", ""), withQuery(usageQuery))
}

func openAIAuditAttributes() map[string]string {
	return map[string]string{
		"api_key_id":               "api_key.created.id|api_key.updated.id|api_key.deleted.id|api_key.id|api_key_id",
		"audit_log_id":             "id",
		"actor_api_key_id":         "actor.api_key.id",
		"actor_city":               "actor.session.ip_address_details.city",
		"actor_country":            "actor.session.ip_address_details.country",
		"actor_email":              "actor.session.user.email|actor.api_key.user.email|actor.user.email|actor.email",
		"actor_id":                 "actor.session.user.id|actor.api_key.user.id|actor.api_key.service_account.id|actor.api_key.id|actor.user.id|actor.service_account.id|actor.id",
		"actor_ip_address":         "actor.session.ip_address",
		"actor_region":             "actor.session.ip_address_details.region",
		"actor_service_account_id": "actor.api_key.service_account.id|actor.service_account.id",
		"actor_type":               "actor.type|actor.api_key.type",
		"actor_user_agent":         "actor.session.user_agent",
		"actor_user_id":            "actor.session.user.id|actor.api_key.user.id|actor.user.id",
		"certificate_id":           "certificate.created.id|certificate.updated.id|certificate.deleted.id",
		"certificate_name":         "certificate.created.name|certificate.updated.name|certificate.deleted.name",
		"effective_at":             "effective_at",
		"event_type":               "type|event_type",
		"external_key_id":          "external_key.registered.id|external_key.removed.id",
		"group_id":                 "group.created.id|group.updated.id|group.deleted.id",
		"group_name":               "group.created.data.group_name|group.updated.changes_requested.group_name",
		"invite_email":             "invite.sent.data.email",
		"invite_id":                "invite.sent.id|invite.accepted.id|invite.deleted.id",
		"invite_role":              "invite.sent.data.role",
		"ip_allowlist_id":          "ip_allowlist.created.id|ip_allowlist.updated.id|ip_allowlist.deleted.id",
		"ip_allowlist_name":        "ip_allowlist.created.name|ip_allowlist.deleted.name",
		"organization_id":          "organization.updated.id|organization_id|org_id",
		"principal_id":             "role.assignment.created.principal_id|role.assignment.deleted.principal_id",
		"principal_type":           "role.assignment.created.principal_type|role.assignment.deleted.principal_type",
		"project_id":               "project.created.id|project.updated.id|project.archived.id|project.deleted.id|checkpoint.permission.created.data.project_id|project.id|project_id",
		"rate_limit_id":            "rate_limit.updated.id|rate_limit.deleted.id",
		"resource_id":              "role.assignment.created.resource_id|role.assignment.deleted.resource_id|role.bound_to_resource.resource_id|role.unbound_from_resource.resource_id|resource.deleted.id",
		"resource_type":            "role.assignment.created.resource_type|role.assignment.deleted.resource_type|role.bound_to_resource.resource_type|role.unbound_from_resource.resource_type|resource.deleted.type",
		"role_assignment_id":       "role.assignment.created.id|role.assignment.deleted.id",
		"role_id":                  "role.created.id|role.updated.id|role.deleted.id|role.bound_to_resource.role_id|role.unbound_from_resource.role_id",
		"role_name":                "role.created.data.role_name|role.updated.changes_requested.role_name|role.bound_to_resource.role_name|role.unbound_from_resource.role_name",
		"service_account_id":       "service_account.created.id|service_account.updated.id|service_account.deleted.id",
		"user_id":                  "user.added.id|user.updated.id|user.deleted.id",
	}
}

func roleAttributes() map[string]string {
	return map[string]string{
		"role_id":         "id",
		"name":            "name",
		"description":     "description",
		"permissions":     "permissions",
		"resource_type":   "resource_type",
		"predefined_role": "predefined_role",
		"created_at":      "created_at",
		"updated_at":      "updated_at",
		"created_by":      "created_by",
	}
}

func projectRateLimitAttributes() map[string]string {
	return map[string]string{ // #nosec G101 -- provider field names only, not credentials.
		"project_id":                   "project_id",
		"rate_limit_id":                "id",
		"model":                        "model",
		"max_requests_per_1_minute":    "max_requests_per_1_minute",
		"max_tokens_per_1_minute":      "max_tokens_per_1_minute",
		"max_images_per_1_minute":      "max_images_per_1_minute",
		"max_requests_per_1_day":       "max_requests_per_1_day",
		"batch_1_day_max_input_tokens": "batch_1_day_max_input_tokens",
	}
}

func withPathParams(params ...string) familyOption {
	return func(f *jsonapi.Family) {
		f.PathParams = append([]string{}, params...)
	}
}

func withStaticAttributes(extra map[string]string) familyOption {
	return func(f *jsonapi.Family) {
		merged := make(map[string]string, len(f.StaticAttributes)+len(extra))
		for key, value := range f.StaticAttributes {
			merged[key] = value
		}
		for key, value := range extra {
			merged[key] = value
		}
		f.StaticAttributes = merged
	}
}

func withQuery(query map[string]string) familyOption {
	return func(f *jsonapi.Family) {
		f.ConfigQuery = query
	}
}

func withCursor(param string, nextKey string, hasMoreKey string) familyOption {
	return func(f *jsonapi.Family) {
		f.CursorParam = param
		f.NextCursorKeys = []string{nextKey}
		f.HasMoreKey = hasMoreKey
	}
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
