package langfuse

import (
	"context"
	"embed"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/sources/internal/jsonapi"
)

//go:embed catalog.yaml
var catalogFS embed.FS

const sourceID = "langfuse"

type Source struct{ inner *jsonapi.Source }

type familyOption func(*jsonapi.Family)

var staticAttributes = map[string]string{"source_product": "langfuse"}

func New() (*Source, error) {
	spec, err := loadSpec()
	if err != nil {
		return nil, err
	}
	inner, err := jsonapi.New(spec, jsonapi.Options{
		SourceID:               sourceID,
		DefaultBaseURL:         "https://cloud.langfuse.com",
		DefaultFamily:          "project",
		RequireTenantID:        true,
		AuthModel:              "basic",
		ConfigurableAuthModels: []string{"basic", "bearer_token"},
		Families:               langfuseFamilies(),
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

func langfuseFamilies() []jsonapi.Family {
	return []jsonapi.Family{
		langfuseListFamily("project", "/api/public/projects", "langfuse_project", []string{"id", "projectId"}, []string{"createdAt", "created_at"}, map[string]string{
			"project_id":      "id|projectId|project_id",
			"name":            "name",
			"organization_id": "organizationId|organization_id",
			"created_at":      "createdAt|created_at",
			"updated_at":      "updatedAt|updated_at",
		}, withPageCursor()),
		langfuseListFamily("project_member", "/api/public/projects/{project_id}/memberships", "langfuse_project_member", []string{"id", "userId", "user_id", "email"}, []string{"createdAt", "updatedAt"}, projectMemberAttributes(), withPathParams("project_id"), withConfigAttributes(map[string]string{"project_id": "project_id"}), withStaticAttributes(map[string]string{"principal_type": "user"}), withPageCursor()),
		langfuseListFamily("api_key", "/api/public/projects/{project_id}/apiKeys", "langfuse_api_key", []string{"id", "apiKeyId", "publicKey"}, []string{"createdAt", "updatedAt", "lastUsedAt", "expiresAt"}, apiKeyAttributes(), withPathParams("project_id"), withConfigAttributes(map[string]string{"project_id": "project_id"}), withStaticAttributes(map[string]string{"credential_type": "langfuse_project_api_key"}), withPageCursor()),
		langfuseListFamily("trace", "/api/public/traces", "langfuse_trace", []string{"id", "traceId"}, []string{"timestamp", "createdAt", "updatedAt"}, traceAttributes(), withPageCursor(), withQuery(map[string]string{"fromTimestamp": "from_timestamp", "toTimestamp": "to_timestamp", "name": "name", "userId": "user_id", "sessionId": "session_id", "release": "release", "version": "version", "tags": "tags", "filter": "filter"})),
		langfuseListFamily("observation", "/api/public/v2/observations", "langfuse_observation", []string{"id", "observationId"}, []string{"startTime", "endTime", "createdAt", "updatedAt"}, observationAttributes(), withPageCursor(), withQuery(map[string]string{"fromStartTime": "from_start_time", "toStartTime": "to_start_time", "traceId": "trace_id", "userId": "user_id", "name": "name", "type": "type", "fields": "fields", "filter": "filter"})),
		langfuseListFamily("score", "/api/public/scores", "langfuse_score", []string{"id", "scoreId"}, []string{"timestamp", "createdAt", "updatedAt"}, map[string]string{
			"score_id":       "id|scoreId",
			"trace_id":       "traceId|trace_id",
			"observation_id": "observationId|observation_id",
			"name":           "name",
			"value":          "value",
			"score_type":     "dataType|scoreType|type",
			"source":         "source",
			"comment":        "comment",
			"user_id":        "userId|user_id",
			"created_at":     "createdAt|created_at|timestamp",
			"updated_at":     "updatedAt|updated_at",
		}, withPageCursor(), withQuery(map[string]string{"traceId": "trace_id", "userId": "user_id", "name": "name", "fromTimestamp": "from_timestamp", "toTimestamp": "to_timestamp"})),
		langfuseListFamily("prompt", "/api/public/prompts", "langfuse_prompt", []string{"id", "name", "promptName"}, []string{"createdAt", "updatedAt"}, map[string]string{
			"prompt_id":    "id|name|promptName",
			"name":         "name|promptName",
			"version":      "version",
			"type":         "type",
			"labels":       "labels",
			"tags":         "tags",
			"created_by":   "createdBy|created_by",
			"created_at":   "createdAt|created_at",
			"updated_at":   "updatedAt|updated_at",
			"last_used_at": "lastUsedAt|last_used_at",
			"project_id":   "projectId|project_id",
			"production":   "production",
			"config":       "config",
		}, withPageCursor(), withQuery(map[string]string{"name": "name", "label": "label", "tag": "tag"})),
		langfuseListFamily("session", "/api/public/sessions", "langfuse_session", []string{"id", "sessionId"}, []string{"createdAt", "updatedAt"}, map[string]string{
			"session_id": "id|sessionId",
			"user_id":    "userId|user_id",
			"name":       "name",
			"created_at": "createdAt|created_at",
			"updated_at": "updatedAt|updated_at",
		}, withPageCursor(), withQuery(map[string]string{"fromTimestamp": "from_timestamp", "toTimestamp": "to_timestamp", "userId": "user_id"})),
		langfuseListFamily("metric", "/api/public/metrics", "langfuse_metric", []string{"id", "name", "metric"}, []string{"timestamp", "createdAt"}, map[string]string{
			"metric_id":     "id|name|metric",
			"metric_type":   "type|metric",
			"name":          "name|metric",
			"trace_name":    "traceName|trace_name",
			"model":         "model",
			"user_id":       "userId|user_id",
			"input_tokens":  "inputTokens|input_tokens",
			"output_tokens": "outputTokens|output_tokens",
			"total_tokens":  "totalTokens|total_tokens",
			"cost_usd":      "totalCost|cost|costUsd|cost_usd",
			"request_count": "count|requestCount|request_count",
			"created_at":    "createdAt|created_at|timestamp",
		}, withPageCursor(), withQuery(map[string]string{"fromTimestamp": "from_timestamp", "toTimestamp": "to_timestamp", "traceName": "trace_name", "userId": "user_id"})),
		langfuseListFamily("annotation_queue", "/api/public/annotation-queues", "langfuse_annotation_queue", []string{"id", "queueId", "name"}, []string{"createdAt", "updatedAt"}, map[string]string{
			"queue_id":    "id|queueId",
			"name":        "name",
			"description": "description",
			"status":      "status",
			"created_at":  "createdAt|created_at",
			"updated_at":  "updatedAt|updated_at",
		}, withPageCursor()),
	}
}

func langfuseListFamily(name string, path string, urnKind string, idKeys []string, timestampKeys []string, attrs map[string]string, opts ...familyOption) jsonapi.Family {
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

func projectMemberAttributes() map[string]string {
	return map[string]string{
		"project_id":   "projectId|project_id",
		"user_id":      "userId|user_id|id|email",
		"email":        "email|user.email",
		"name":         "name|user.name",
		"role":         "role|roleName|role_name",
		"role_id":      "roleId|role_id",
		"principal_id": "userId|user_id|id",
		"created_at":   "createdAt|created_at",
		"updated_at":   "updatedAt|updated_at",
	}
}

func apiKeyAttributes() map[string]string {
	return map[string]string{ // #nosec G101 -- provider API field names only, not credential material.
		"api_key_id":    "id|apiKeyId|publicKey",
		"credential_id": "id|apiKeyId|publicKey",
		"name":          "name|label|note",
		"public_key":    "publicKey|public_key",
		"status":        "status",
		"project_id":    "projectId|project_id",
		"created_at":    "createdAt|created_at",
		"updated_at":    "updatedAt|updated_at",
		"last_used_at":  "lastUsedAt|last_used_at",
		"expires_at":    "expiresAt|expires_at",
	}
}

func traceAttributes() map[string]string {
	return map[string]string{
		"trace_id":      "id|traceId",
		"name":          "name",
		"user_id":       "userId|user_id",
		"session_id":    "sessionId|session_id",
		"release":       "release",
		"version":       "version",
		"tags":          "tags",
		"environment":   "environment",
		"public":        "public",
		"metadata":      "metadata",
		"created_at":    "timestamp|createdAt|created_at",
		"input_tokens":  "inputTokens|input_tokens",
		"output_tokens": "outputTokens|output_tokens",
		"total_tokens":  "totalTokens|total_tokens",
		"cost_usd":      "totalCost|cost|costUsd|cost_usd",
	}
}

func observationAttributes() map[string]string {
	return map[string]string{
		"observation_id": "id|observationId",
		"trace_id":       "traceId|trace_id",
		"parent_id":      "parentObservationId|parent_observation_id",
		"name":           "name",
		"type":           "type",
		"level":          "level",
		"status":         "statusMessage|status",
		"user_id":        "userId|user_id",
		"model":          "model",
		"input_tokens":   "usage.input|usage.inputTokens|inputTokens|input_tokens",
		"output_tokens":  "usage.output|usage.outputTokens|outputTokens|output_tokens",
		"total_tokens":   "usage.total|usage.totalTokens|totalTokens|total_tokens",
		"cost_usd":       "costDetails.total|totalCost|costUsd|cost_usd",
		"start_time":     "startTime|start_time",
		"end_time":       "endTime|end_time",
		"created_at":     "createdAt|created_at|startTime",
		"updated_at":     "updatedAt|updated_at",
	}
}

func withPathParams(params ...string) familyOption {
	return func(f *jsonapi.Family) {
		f.PathParams = append([]string{}, params...)
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

func withPageCursor() familyOption {
	return func(f *jsonapi.Family) {
		f.CursorParam = "page"
		f.NextCursorKeys = []string{"nextPage", "next_page"}
		f.PageFirstCursor = "1"
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
