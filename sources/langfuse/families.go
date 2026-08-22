package langfuse

import "github.com/writer/cerebro/sources/internal/jsonapi"

type familyOption func(*jsonapi.Family)

var staticAttributes = map[string]string{"source_product": "langfuse"}

func langfuseFamilies() []jsonapi.Family {
	return []jsonapi.Family{
		langfuseListFamily("project", "/api/public/projects", "langfuse_project", []string{"id", "projectId"}, []string{"createdAt", "created_at"}, map[string]string{
			"project_id":      "id|projectId|project_id",
			"name":            "name",
			"organization_id": "organizationId|organization_id",
			"created_at":      "createdAt|created_at",
			"updated_at":      "updatedAt|updated_at",
		}, withListKeys("data"), withoutPagination()),
		langfuseListFamily("project_member", "/api/public/projects/{project_id}/memberships", "langfuse_project_member", []string{"id", "userId", "user_id", "email"}, []string{"createdAt", "updatedAt"}, projectMemberAttributes(), withPathParams("project_id"), withConfigAttributes(map[string]string{"project_id": "project_id"}), withStaticAttributes(map[string]string{"principal_type": "user"}), withListKeys("memberships"), withoutPagination()),
		langfuseListFamily("api_key", "/api/public/projects/{project_id}/apiKeys", "langfuse_api_key", []string{"id", "apiKeyId", "publicKey"}, []string{"createdAt", "updatedAt", "lastUsedAt", "expiresAt"}, apiKeyAttributes(), withPathParams("project_id"), withConfigAttributes(map[string]string{"project_id": "project_id"}), withStaticAttributes(map[string]string{"credential_type": "langfuse_project_api_key"}), withListKeys("apiKeys"), withoutPagination()),
		langfuseListFamily("trace", "/api/public/traces", "langfuse_trace", []string{"id", "traceId"}, []string{"timestamp", "createdAt", "updatedAt"}, traceAttributes(), withPageCursor(), withQuery(map[string]string{"fromTimestamp": "from_timestamp", "toTimestamp": "to_timestamp", "name": "name", "userId": "user_id", "sessionId": "session_id", "release": "release", "version": "version", "tags": "tags", "filter": "filter"})),
		langfuseObservationFamily("/api/public/v2/observations", withCursor("cursor", "meta.cursor")),
		langfuseListFamily("score", "/api/public/v2/scores", "langfuse_score", []string{"id", "scoreId"}, []string{"timestamp", "createdAt", "updatedAt"}, map[string]string{
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
		langfuseListFamily("prompt", "/api/public/v2/prompts", "langfuse_prompt", []string{"name"}, []string{"lastUpdatedAt"}, map[string]string{
			"prompt_id":       "name",
			"name":            "name",
			"type":            "type",
			"versions":        "versions",
			"labels":          "labels",
			"tags":            "tags",
			"last_updated_at": "lastUpdatedAt",
			"last_config":     "lastConfig",
		}, withPageCursor(), withQuery(map[string]string{"name": "name", "label": "label", "tag": "tag"})),
		langfuseListFamily("session", "/api/public/sessions", "langfuse_session", []string{"id", "sessionId"}, []string{"createdAt", "updatedAt"}, map[string]string{
			"session_id": "id|sessionId",
			"user_id":    "userId|user_id",
			"name":       "name",
			"created_at": "createdAt|created_at",
			"updated_at": "updatedAt|updated_at",
		}, withPageCursor(), withQuery(map[string]string{"fromTimestamp": "from_timestamp", "toTimestamp": "to_timestamp", "userId": "user_id"})),
		langfuseMetricFamily("/api/public/v2/metrics"),
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

func langfuseLegacyFallbackFamilies() []jsonapi.Family {
	return []jsonapi.Family{
		langfuseObservationFamily("/api/public/observations", withPageCursor()),
		langfuseMetricFamily("/api/public/metrics"),
	}
}

func langfuseObservationFamily(path string, pagination familyOption) jsonapi.Family {
	return langfuseListFamily("observation", path, "langfuse_observation", []string{"id", "observationId"}, []string{"startTime", "endTime", "createdAt", "updatedAt"}, observationAttributes(), pagination, withQuery(map[string]string{"fromStartTime": "from_start_time", "toStartTime": "to_start_time", "traceId": "trace_id", "userId": "user_id", "name": "name", "type": "type", "fields": "fields", "filter": "filter"}))
}

func langfuseMetricFamily(path string) jsonapi.Family {
	return langfuseListFamily("metric", path, "langfuse_metric", []string{"name", "metric"}, nil, map[string]string{
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
		"request_count": "count|count_count|requestCount|request_count",
		"created_at":    "createdAt|created_at|timestamp",
	}, withQuery(map[string]string{"query": "metrics_query"}), withoutPagination())
}

func langfuseListFamily(name string, path string, urnKind string, idKeys []string, timestampKeys []string, attrs map[string]string, opts ...familyOption) jsonapi.Family {
	family := jsonapi.Family{Name: name, Path: path, URNKind: urnKind, IDKeys: idKeys, TimestampKeys: timestampKeys, Attributes: attrs, StaticAttributes: staticAttributes, PageSizeParams: []string{"limit"}}
	for _, opt := range opts {
		opt(&family)
	}
	return family
}

func projectMemberAttributes() map[string]string {
	return map[string]string{
		"project_id": "projectId|project_id", "user_id": "userId|user_id|id|email", "email": "email|user.email", "name": "name|user.name", "role": "role|roleName|role_name", "role_id": "roleId|role_id", "principal_id": "userId|user_id|id", "created_at": "createdAt|created_at", "updated_at": "updatedAt|updated_at",
	}
}

func apiKeyAttributes() map[string]string {
	return map[string]string{ // #nosec G101 -- provider API field names only, not credential material.
		"api_key_id": "id|apiKeyId|publicKey", "credential_id": "id|apiKeyId|publicKey", "name": "name|label|note", "public_key": "publicKey|public_key", "status": "status", "project_id": "projectId|project_id", "created_at": "createdAt|created_at", "updated_at": "updatedAt|updated_at", "last_used_at": "lastUsedAt|last_used_at", "expires_at": "expiresAt|expires_at",
	}
}

func traceAttributes() map[string]string {
	return map[string]string{
		"trace_id": "id|traceId", "name": "name", "user_id": "userId|user_id", "session_id": "sessionId|session_id", "release": "release", "version": "version", "tags": "tags", "environment": "environment", "public": "public", "metadata": "metadata", "created_at": "timestamp|createdAt|created_at", "input_tokens": "inputTokens|input_tokens", "output_tokens": "outputTokens|output_tokens", "total_tokens": "totalTokens|total_tokens", "cost_usd": "totalCost|cost|costUsd|cost_usd",
	}
}

func observationAttributes() map[string]string {
	return map[string]string{
		"observation_id": "id|observationId", "trace_id": "traceId|trace_id", "parent_id": "parentObservationId|parent_observation_id", "name": "name", "type": "type", "level": "level", "status": "statusMessage|status", "user_id": "userId|user_id", "model": "model", "input_tokens": "usage.input|usage.inputTokens|inputTokens|input_tokens", "output_tokens": "usage.output|usage.outputTokens|outputTokens|output_tokens", "total_tokens": "usage.total|usage.totalTokens|totalTokens|total_tokens", "cost_usd": "costDetails.total|totalCost|costUsd|cost_usd", "start_time": "startTime|start_time", "end_time": "endTime|end_time", "created_at": "createdAt|created_at|startTime", "updated_at": "updatedAt|updated_at",
	}
}

func withPathParams(params ...string) familyOption {
	return func(f *jsonapi.Family) { f.PathParams = append([]string{}, params...) }
}

func withConfigAttributes(attrs map[string]string) familyOption {
	return func(f *jsonapi.Family) { f.Config.ConfigAttributes = attrs }
}

func withStaticAttributes(extra map[string]string) familyOption {
	return func(f *jsonapi.Family) { jsonapi.MergeStaticAttributes(f, extra) }
}

func withPageCursor() familyOption {
	return func(f *jsonapi.Family) {
		f.CursorParam = "page"
		f.NextCursorKeys = []string{"nextPage", "next_page"}
		f.PageFirstCursor = "1"
	}
}

func withCursor(param string, responseKey string) familyOption {
	return func(f *jsonapi.Family) {
		f.CursorParam = param
		f.NextCursorKeys = []string{responseKey}
	}
}

func withListKeys(keys ...string) familyOption {
	return func(f *jsonapi.Family) { f.ListKeys = append([]string{}, keys...) }
}

func withoutPagination() familyOption {
	return func(f *jsonapi.Family) {
		f.DisablePageSize = true
	}
}

func withQuery(query map[string]string) familyOption {
	return func(f *jsonapi.Family) { f.Config.ConfigQuery = query }
}
