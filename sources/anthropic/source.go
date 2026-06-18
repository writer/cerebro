package anthropic

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

const sourceID = "anthropic"

type Source struct{ inner *jsonapi.Source }

type familyOption func(*jsonapi.Family)

var (
	staticAttributes = map[string]string{"source_product": "anthropic"}
	reportQuery      = map[string]string{
		"api_key_ids[]":    "api_key_ids",
		"bucket_width":     "bucket_width",
		"context_window[]": "context_windows",
		"ending_at":        "ending_at",
		"group_by[]":       "group_by",
		"inference_geos[]": "inference_geos",
		"models[]":         "models",
		"service_tiers[]":  "service_tiers",
		"speeds[]":         "speeds",
		"starting_at":      "starting_at",
		"terminal_types[]": "terminal_types",
		"workspace_ids[]":  "workspace_ids",
	}
)

func New() (*Source, error) {
	spec, err := loadSpec()
	if err != nil {
		return nil, err
	}
	inner, err := jsonapi.New(spec, jsonapi.Options{
		SourceID:               sourceID,
		DefaultBaseURL:         "https://api.anthropic.com/v1",
		DefaultFamily:          "user",
		RequireTenantID:        true,
		TokenHeader:            "x-api-key",
		StaticHeaders:          map[string]string{"anthropic-version": "2023-06-01"},
		ConfigurableAuthModels: []string{"legacy_token", "api_key", "bearer_token"},
		Families:               anthropicFamilies(),
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

func anthropicFamilies() []jsonapi.Family {
	return []jsonapi.Family{
		anthropicSingletonFamily("organization", "/organizations/me", "anthropic_organization", map[string]string{"organization_id": "id", "name": "name", "type": "type"}),
		anthropicListFamily("user", "/organizations/users", "anthropic_user", []string{"id"}, []string{"added_at"}, map[string]string{"user_id": "id", "name": "name", "email": "email", "role": "role", "status": "status", "added_at": "added_at"}),
		anthropicListFamily("invite", "/organizations/invites", "anthropic_invite", []string{"id"}, []string{"created_at", "expires_at"}, map[string]string{"invite_id": "id", "email": "email", "role": "role", "status": "status", "created_at": "created_at", "expires_at": "expires_at"}),
		anthropicListFamily("workspace", "/organizations/workspaces", "anthropic_workspace", []string{"id"}, []string{"created_at", "archived_at"}, map[string]string{"workspace_id": "id", "name": "name", "display_color": "display_color", "created_at": "created_at", "archived_at": "archived_at"}, withQuery(map[string]string{"include_archived": "include_archived"})),
		anthropicListFamily("workspace_member", "/organizations/workspaces/{workspace_id}/members", "anthropic_workspace_member", []string{"id", "user_id"}, []string{"added_at", "created_at"}, map[string]string{"workspace_id": "workspace_id", "user_id": "id|user_id", "email": "email", "name": "name", "workspace_role": "workspace_role|role", "added_at": "added_at"}, withPathParams("workspace_id")),
		anthropicListFamily("api_key", "/organizations/api_keys", "anthropic_api_key", []string{"id"}, []string{"created_at", "last_used_at"}, map[string]string{"api_key_id": "id", "name": "name", "status": "status", "workspace_id": "workspace_id|workspace.id", "owner_user_id": "created_by.id|owner.id|user_id", "created_at": "created_at", "last_used_at": "last_used_at"}, withQuery(map[string]string{"status": "status", "workspace_id": "workspace_id"})),
		anthropicListFamily("external_key", "/organizations/external_keys", "anthropic_external_key", []string{"id"}, []string{"created_at", "last_used_at"}, map[string]string{"external_key_id": "id", "name": "name", "status": "status", "provider": "provider", "workspace_id": "workspace_id|workspace.id", "created_at": "created_at", "last_used_at": "last_used_at"}, withPageCursor()),
		anthropicListFamily("service_account", "/organizations/service_accounts", "anthropic_service_account", []string{"id"}, []string{"created_at"}, map[string]string{"service_account_id": "id", "name": "name", "status": "status", "description": "description", "created_at": "created_at"}),
		anthropicListFamily("federation_issuer", "/organizations/federation_issuers", "anthropic_federation_issuer", []string{"id"}, []string{"created_at", "updated_at"}, map[string]string{"federation_issuer_id": "id", "issuer": "issuer", "name": "name", "status": "status", "created_at": "created_at", "updated_at": "updated_at"}),
		anthropicListFamily("federation_rule", "/organizations/federation_rules", "anthropic_federation_rule", []string{"id"}, []string{"created_at", "updated_at"}, map[string]string{"federation_rule_id": "id", "issuer_id": "issuer_id|federation_issuer_id", "service_account_id": "service_account_id", "subject": "subject", "scopes": "scopes", "created_at": "created_at", "updated_at": "updated_at"}),
		anthropicReportFamily("usage_report_message", "/organizations/usage_report/messages"),
		anthropicReportFamily("usage_report_claude_code", "/organizations/usage_report/claude_code"),
		anthropicReportFamily("cost_report", "/organizations/cost_report"),
		anthropicReportFamily("analytics_cost", "/organizations/analytics/cost"),
		anthropicListFamily("rate_limit", "/organizations/rate_limits", "anthropic_rate_limit", []string{"id", "group_type", "model", "name"}, []string{"updated_at"}, rateLimitAttributes(), withQuery(map[string]string{"model": "model"}), withPageCursor()),
		anthropicListFamily("workspace_rate_limit", "/organizations/workspaces/{workspace_id}/rate_limits", "anthropic_workspace_rate_limit", []string{"id", "group_type", "model", "name"}, []string{"updated_at"}, rateLimitAttributes(), withPathParams("workspace_id"), withPageCursor()),
		anthropicListFamily("spend_limit", "/organizations/spend_limits/effective", "anthropic_spend_limit", []string{"spend_limit_id", "id", "scope.user_id", "actor.user_id"}, []string{"created_at", "updated_at"}, map[string]string{"spend_limit_id": "spend_limit_id|id", "scope_type": "scope.type", "user_id": "scope.user_id|actor.user_id", "actor_email": "actor.email_address|actor.email", "amount": "amount", "currency": "currency", "period": "period", "source_type": "source.type", "period_to_date_spend": "period_to_date_spend", "created_at": "created_at", "updated_at": "updated_at"}, withPageCursor(), withQuery(map[string]string{"actor_ids[]": "actor_ids", "period[]": "periods", "user_ids[]": "user_ids"})),
		anthropicListFamily("spend_limit_increase_request", "/organizations/spend_limit_increase_requests", "anthropic_spend_limit_increase_request", []string{"id"}, []string{"created_at", "updated_at"}, map[string]string{"request_id": "id", "user_id": "scope.user_id|actor.user_id", "actor_email": "actor.email_address|actor.email", "status": "status", "amount": "amount", "currency": "currency", "period": "period", "created_at": "created_at", "updated_at": "updated_at"}, withPageCursor(), withQuery(map[string]string{"actor_ids[]": "actor_ids", "status[]": "status"})),
		anthropicListFamily("compliance_activity", "/compliance/activities", "anthropic_compliance_activity", []string{"id"}, []string{"created_at"}, map[string]string{"activity_id": "id", "activity_type": "type", "organization_id": "organization_id", "organization_uuid": "organization_uuid", "actor_type": "actor.type", "actor_user_id": "actor.user_id", "actor_api_key_id": "actor.api_key_id", "actor_email": "actor.email_address|actor.email", "created_at": "created_at"}, withQuery(map[string]string{"activity_types[]": "activity_types", "actor_ids[]": "actor_ids", "created_at.gt": "created_at_gt", "created_at.gte": "created_at_gte", "created_at.lt": "created_at_lt", "created_at.lte": "created_at_lte", "organization_ids[]": "organization_ids"})),
	}
}

func anthropicListFamily(name string, path string, urnKind string, idKeys []string, timestampKeys []string, attrs map[string]string, opts ...familyOption) jsonapi.Family {
	family := jsonapi.Family{
		Name:             name,
		Path:             path,
		CursorParam:      "after_id",
		NextCursorKeys:   []string{"last_id", "next_page"},
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

func anthropicSingletonFamily(name string, path string, urnKind string, attrs map[string]string, opts ...familyOption) jsonapi.Family {
	return anthropicListFamily(name, path, urnKind, []string{"id"}, nil, attrs, append(opts, func(f *jsonapi.Family) {
		f.Singleton = true
		f.DisablePageSize = true
		f.CursorParam = ""
		f.NextCursorKeys = nil
		f.HasMoreKey = ""
	})...)
}

func anthropicReportFamily(name string, path string) jsonapi.Family {
	return anthropicListFamily(name, path, "anthropic_"+name, []string{"id"}, []string{"start_time", "starting_at", "date"}, map[string]string{
		"start_time":      "start_time|starting_at|date",
		"end_time":        "end_time|ending_at",
		"workspace_id":    "workspace_id",
		"user_id":         "user_id",
		"api_key_id":      "api_key_id",
		"model":           "model",
		"cost_usd":        "cost_usd|cost",
		"input_tokens":    "input_tokens",
		"output_tokens":   "output_tokens",
		"request_count":   "request_count|requests",
		"organization_id": "organization_id",
	}, withPageCursor(), withQuery(reportQuery))
}

func rateLimitAttributes() map[string]string {
	return map[string]string{ // #nosec G101 -- provider field names only, not credentials.
		"rate_limit_id":       "id",
		"group_type":          "group_type",
		"name":                "name",
		"model":               "model",
		"models":              "models",
		"workspace_id":        "workspace_id",
		"limits":              "limits",
		"requests_per_minute": "requests_per_minute|rpm",
		"tokens_per_minute":   "tokens_per_minute|tpm",
		"input_tokens":        "input_tokens",
		"output_tokens":       "output_tokens",
		"updated_at":          "updated_at",
	}
}

func withPathParams(params ...string) familyOption {
	return func(f *jsonapi.Family) {
		f.PathParams = append([]string{}, params...)
	}
}

func withQuery(query map[string]string) familyOption {
	return func(f *jsonapi.Family) {
		f.ConfigQuery = query
	}
}

func withPageCursor() familyOption {
	return func(f *jsonapi.Family) {
		f.CursorParam = "page"
		f.NextCursorKeys = []string{"next_page"}
		f.HasMoreKey = ""
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
