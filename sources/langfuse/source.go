package langfuse

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/sources/internal/jsonapi"
)

//go:embed catalog.yaml
var catalogFS embed.FS

const sourceID = "langfuse"

type Source struct {
	inner          *jsonapi.Source
	legacyFallback *jsonapi.Source
}

type familyOption func(*jsonapi.Family)

var staticAttributes = map[string]string{"source_product": "langfuse"}

func New() (*Source, error) {
	spec, err := loadSpec()
	if err != nil {
		return nil, err
	}
	options := jsonapi.Options{
		SourceID:               sourceID,
		DefaultBaseURL:         "https://cloud.langfuse.com",
		DefaultFamily:          "project",
		RequireTenantID:        true,
		AuthModel:              "basic",
		ConfigurableAuthModels: []string{"basic", "bearer_token"},
		Families:               langfuseFamilies(),
		DoNotRetryStatuses:     []int{http.StatusNotImplemented},
	}
	inner, err := jsonapi.New(spec, options)
	if err != nil {
		return nil, err
	}
	options.Families = langfuseLegacyFallbackFamilies()
	legacyFallback, err := jsonapi.New(spec, options)
	if err != nil {
		return nil, err
	}
	return &Source{inner: inner, legacyFallback: legacyFallback}, nil
}

func (s *Source) Spec() *cerebrov1.SourceSpec { return s.inner.Spec() }
func (s *Source) Check(ctx context.Context, cfg sourcecdk.Config) error {
	if err := validateMetricsQuery(cfg); err != nil {
		return err
	}
	err := s.inner.Check(ctx, cfg)
	if !isLangfuseV2Fallback(cfg, err) {
		return err
	}
	s.syncFallbackTransport()
	return s.legacyFallback.Check(ctx, cfg)
}
func (s *Source) Discover(ctx context.Context, cfg sourcecdk.Config) ([]sourcecdk.URN, error) {
	if err := validateMetricsQuery(cfg); err != nil {
		return nil, err
	}
	urns, err := s.inner.Discover(ctx, cfg)
	if !isLangfuseV2Fallback(cfg, err) {
		return urns, err
	}
	s.syncFallbackTransport()
	return s.legacyFallback.Discover(ctx, cfg)
}
func (s *Source) Read(ctx context.Context, cfg sourcecdk.Config, cursor *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
	if err := validateMetricsQuery(cfg); err != nil {
		return sourcecdk.Pull{}, err
	}
	family, _ := cfg.Lookup("family")
	family = strings.TrimSpace(family)
	if legacyCursor, ok := langfuseLegacyCursor(family, cursor); ok {
		s.syncFallbackTransport()
		pull, err := s.legacyFallback.Read(ctx, cfg, legacyCursor)
		return markLangfuseLegacyCursor(pull), err
	}
	pull, err := s.inner.Read(ctx, cfg, cursor)
	if !isLangfuseV2Fallback(cfg, err) || strings.TrimSpace(sourcecdk.CursorToken(cursor)) != "" {
		return pull, err
	}
	s.syncFallbackTransport()
	pull, err = s.legacyFallback.Read(ctx, cfg, nil)
	return markLangfuseLegacyCursor(pull), err
}

const langfuseLegacyCursorPrefix = "langfuse-v1:"

type statusCodeError interface{ StatusCode() int }

func isLangfuseV2Fallback(cfg sourcecdk.Config, err error) bool {
	if err == nil {
		return false
	}
	family, _ := cfg.Lookup("family")
	if family = strings.TrimSpace(family); family != "observation" && family != "metric" {
		return false
	}
	var statusErr statusCodeError
	return errors.As(err, &statusErr) && statusErr.StatusCode() == http.StatusNotImplemented
}

func (s *Source) syncFallbackTransport() {
	if s != nil && s.inner != nil && s.legacyFallback != nil {
		s.legacyFallback.AllowLoopbackBaseURL = s.inner.AllowLoopbackBaseURL
	}
}

func langfuseLegacyCursor(family string, cursor *cerebrov1.SourceCursor) (*cerebrov1.SourceCursor, bool) {
	if family != "observation" && family != "metric" {
		return nil, false
	}
	token := strings.TrimSpace(sourcecdk.CursorToken(cursor))
	if !strings.HasPrefix(token, langfuseLegacyCursorPrefix) {
		return nil, false
	}
	return &cerebrov1.SourceCursor{Opaque: strings.TrimPrefix(token, langfuseLegacyCursorPrefix)}, true
}

func markLangfuseLegacyCursor(pull sourcecdk.Pull) sourcecdk.Pull {
	if pull.NextCursor != nil {
		if token := strings.TrimSpace(pull.NextCursor.GetOpaque()); token != "" {
			pull.NextCursor.Opaque = langfuseLegacyCursorPrefix + token
		}
	}
	return pull
}

type metricsQuery struct {
	View       string `json:"view"`
	Dimensions []struct {
		Field string `json:"field"`
	} `json:"dimensions"`
	Metrics []struct {
		Measure     string `json:"measure"`
		Aggregation string `json:"aggregation"`
	} `json:"metrics"`
	FromTimestamp string `json:"fromTimestamp"`
	ToTimestamp   string `json:"toTimestamp"`
}

func validateMetricsQuery(cfg sourcecdk.Config) error {
	family, _ := cfg.Lookup("family")
	if strings.TrimSpace(family) != "metric" {
		return nil
	}
	raw, _ := cfg.Lookup("metrics_query")
	raw = strings.TrimSpace(raw)
	if raw == "" || len(raw) > 16<<10 {
		return fmt.Errorf("langfuse metrics_query must be bounded JSON")
	}
	var query metricsQuery
	if err := json.Unmarshal([]byte(raw), &query); err != nil {
		return fmt.Errorf("langfuse metrics_query must match the documented v2 query schema: %w", err)
	}
	allowedViews := map[string]bool{"observations": true, "scores-numeric": true, "scores-boolean": true, "scores-categorical": true}
	if !allowedViews[query.View] || len(query.Metrics) < 1 || len(query.Metrics) > 16 {
		return fmt.Errorf("langfuse metrics_query requires one supported view and 1 to 16 metrics")
	}
	stableNameDimension := false
	for _, dimension := range query.Dimensions {
		if dimension.Field == "name" {
			stableNameDimension = true
		}
	}
	if !stableNameDimension {
		return fmt.Errorf("langfuse metrics_query requires the name dimension for stable metric IDs")
	}
	from, err := time.Parse(time.RFC3339, query.FromTimestamp)
	if err != nil {
		return fmt.Errorf("langfuse metrics_query fromTimestamp must be RFC3339")
	}
	to, err := time.Parse(time.RFC3339, query.ToTimestamp)
	if err != nil {
		return fmt.Errorf("langfuse metrics_query toTimestamp must be RFC3339")
	}
	if !to.After(from) || to.Sub(from) > 31*24*time.Hour {
		return fmt.Errorf("langfuse metrics_query interval must be positive and at most 31 days")
	}
	for _, metric := range query.Metrics {
		if strings.TrimSpace(metric.Measure) == "" || strings.TrimSpace(metric.Aggregation) == "" {
			return fmt.Errorf("langfuse metrics_query metrics require measure and aggregation")
		}
	}
	return nil
}

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

func withCursor(param string, responseKey string) familyOption {
	return func(f *jsonapi.Family) {
		f.CursorParam = param
		f.NextCursorKeys = []string{responseKey}
		f.PageFirstCursor = ""
	}
}

func withListKeys(keys ...string) familyOption {
	return func(f *jsonapi.Family) {
		f.ListKeys = append([]string{}, keys...)
	}
}

func withoutPagination() familyOption {
	return func(f *jsonapi.Family) {
		f.CursorParam = ""
		f.NextCursorKeys = nil
		f.PageFirstCursor = ""
		f.DisablePageSize = true
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
