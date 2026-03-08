package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	apicontract "github.com/evalops/cerebro/api"
	"gopkg.in/yaml.v3"
)

type openAPIContractCase struct {
	name           string
	method         string
	pathTemplate   string
	requestPath    string
	body           interface{}
	expectedStatus int
}

func TestOpenAPIContract_CriticalRoutes(t *testing.T) {
	spec := loadOpenAPISpec(t)
	s := newTestServer(t)

	cases := []openAPIContractCase{
		{
			name:           "executive summary response contract",
			method:         http.MethodGet,
			pathTemplate:   "/api/v1/reports/executive-summary",
			requestPath:    "/api/v1/reports/executive-summary",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "risk summary response contract",
			method:         http.MethodGet,
			pathTemplate:   "/api/v1/reports/risk-summary",
			requestPath:    "/api/v1/reports/risk-summary",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "scan watermark stats response contract",
			method:         http.MethodGet,
			pathTemplate:   "/api/v1/scan/watermarks",
			requestPath:    "/api/v1/scan/watermarks",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "scan coverage degraded response contract",
			method:         http.MethodGet,
			pathTemplate:   "/api/v1/scan/coverage",
			requestPath:    "/api/v1/scan/coverage",
			expectedStatus: http.StatusServiceUnavailable,
		},
		{
			name:           "sync relationship backfill unavailable contract",
			method:         http.MethodPost,
			pathTemplate:   "/api/v1/sync/backfill-relationships",
			requestPath:    "/api/v1/sync/backfill-relationships",
			body:           map[string]interface{}{"batch_size": 200},
			expectedStatus: http.StatusServiceUnavailable,
		},
		{
			name:           "sync aws unavailable contract",
			method:         http.MethodPost,
			pathTemplate:   "/api/v1/sync/aws",
			requestPath:    "/api/v1/sync/aws",
			body:           map[string]interface{}{"region": "us-west-2", "tables": []string{"aws_iam_users"}},
			expectedStatus: http.StatusServiceUnavailable,
		},
		{
			name:           "sync azure unavailable contract",
			method:         http.MethodPost,
			pathTemplate:   "/api/v1/sync/azure",
			requestPath:    "/api/v1/sync/azure",
			body:           map[string]interface{}{"concurrency": 5, "tables": []string{"azure_vm_instances"}},
			expectedStatus: http.StatusServiceUnavailable,
		},
		{
			name:           "sync k8s unavailable contract",
			method:         http.MethodPost,
			pathTemplate:   "/api/v1/sync/k8s",
			requestPath:    "/api/v1/sync/k8s",
			body:           map[string]interface{}{"namespace": "default", "tables": []string{"k8s_pods"}},
			expectedStatus: http.StatusServiceUnavailable,
		},
		{
			name:           "sync gcp unavailable contract",
			method:         http.MethodPost,
			pathTemplate:   "/api/v1/sync/gcp",
			requestPath:    "/api/v1/sync/gcp",
			body:           map[string]interface{}{"project": "my-project", "tables": []string{"gcp_compute_instances"}},
			expectedStatus: http.StatusServiceUnavailable,
		},
		{
			name:           "sync gcp asset unavailable contract",
			method:         http.MethodPost,
			pathTemplate:   "/api/v1/sync/gcp-asset",
			requestPath:    "/api/v1/sync/gcp-asset",
			body:           map[string]interface{}{"projects": []string{"my-project"}, "tables": []string{"gcp_compute_instances"}},
			expectedStatus: http.StatusServiceUnavailable,
		},
		{
			name:           "threat intel stats response contract",
			method:         http.MethodGet,
			pathTemplate:   "/api/v1/threatintel/stats",
			requestPath:    "/api/v1/threatintel/stats",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "threat intel cve lookup response contract",
			method:         http.MethodGet,
			pathTemplate:   "/api/v1/threatintel/lookup/cve/{cve}",
			requestPath:    "/api/v1/threatintel/lookup/cve/CVE-2025-0001",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "scheduler run unavailable contract",
			method:         http.MethodPost,
			pathTemplate:   "/api/v1/scheduler/jobs/{name}/run",
			requestPath:    "/api/v1/scheduler/jobs/not-a-job/run",
			expectedStatus: http.StatusServiceUnavailable,
		},
		{
			name:           "provider test not found contract",
			method:         http.MethodPost,
			pathTemplate:   "/api/v1/providers/{name}/test",
			requestPath:    "/api/v1/providers/not-a-provider/test",
			expectedStatus: http.StatusNotFound,
		},
		{
			name:           "telemetry ingest contract",
			method:         http.MethodPost,
			pathTemplate:   "/api/v1/telemetry/ingest",
			requestPath:    "/api/v1/telemetry/ingest",
			body:           map[string]interface{}{"events": []map[string]interface{}{}},
			expectedStatus: http.StatusOK,
		},
		{
			name:           "policies list contract",
			method:         http.MethodGet,
			pathTemplate:   "/api/v1/policies",
			requestPath:    "/api/v1/policies/",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "policy create contract",
			method:         http.MethodPost,
			pathTemplate:   "/api/v1/policies",
			requestPath:    "/api/v1/policies/",
			body:           map[string]interface{}{"id": "openapi-policy", "name": "OpenAPI Policy", "effect": "forbid", "resource": "aws::s3::bucket", "conditions": []string{"public == true"}, "severity": "high"},
			expectedStatus: http.StatusCreated,
		},
		{
			name:           "findings list contract",
			method:         http.MethodGet,
			pathTemplate:   "/api/v1/findings",
			requestPath:    "/api/v1/findings/",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "findings scan unavailable contract",
			method:         http.MethodPost,
			pathTemplate:   "/api/v1/findings/scan",
			requestPath:    "/api/v1/findings/scan",
			body:           map[string]interface{}{"tables": []string{"aws_s3_buckets"}, "limit": 25},
			expectedStatus: http.StatusServiceUnavailable,
		},
		{
			name:           "agents list contract",
			method:         http.MethodGet,
			pathTemplate:   "/api/v1/agents",
			requestPath:    "/api/v1/agents/",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "webhooks list contract",
			method:         http.MethodGet,
			pathTemplate:   "/api/v1/webhooks",
			requestPath:    "/api/v1/webhooks/",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "webhook create contract",
			method:         http.MethodPost,
			pathTemplate:   "/api/v1/webhooks",
			requestPath:    "/api/v1/webhooks/",
			body:           map[string]interface{}{"url": "https://example.com/openapi-webhook", "events": []string{"finding.created"}},
			expectedStatus: http.StatusCreated,
		},
		{
			name:           "scheduler jobs list contract",
			method:         http.MethodGet,
			pathTemplate:   "/api/v1/scheduler/jobs",
			requestPath:    "/api/v1/scheduler/jobs",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "attack paths list contract",
			method:         http.MethodGet,
			pathTemplate:   "/api/v1/attack-paths",
			requestPath:    "/api/v1/attack-paths/",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "notifications list contract",
			method:         http.MethodGet,
			pathTemplate:   "/api/v1/notifications",
			requestPath:    "/api/v1/notifications/",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "providers list contract",
			method:         http.MethodGet,
			pathTemplate:   "/api/v1/providers",
			requestPath:    "/api/v1/providers/",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "remediation rules list contract",
			method:         http.MethodGet,
			pathTemplate:   "/api/v1/remediation/rules",
			requestPath:    "/api/v1/remediation/rules",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "remediation rule create contract",
			method:         http.MethodPost,
			pathTemplate:   "/api/v1/remediation/rules",
			requestPath:    "/api/v1/remediation/rules",
			body:           map[string]interface{}{"id": "openapi-rule", "name": "OpenAPI Rule", "enabled": true, "trigger": map[string]interface{}{"type": "finding.created", "severity": "high"}, "actions": []map[string]interface{}{{"type": "create_ticket", "config": map[string]string{"priority": "high"}}}},
			expectedStatus: http.StatusCreated,
		},
		{
			name:           "runtime detections list contract",
			method:         http.MethodGet,
			pathTemplate:   "/api/v1/runtime/detections",
			requestPath:    "/api/v1/runtime/detections",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "runtime responses list contract",
			method:         http.MethodGet,
			pathTemplate:   "/api/v1/runtime/responses",
			requestPath:    "/api/v1/runtime/responses",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "identity reviews list contract",
			method:         http.MethodGet,
			pathTemplate:   "/api/v1/identity/reviews",
			requestPath:    "/api/v1/identity/reviews",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "compliance frameworks list contract",
			method:         http.MethodGet,
			pathTemplate:   "/api/v1/compliance/frameworks",
			requestPath:    "/api/v1/compliance/frameworks",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "tickets list contract",
			method:         http.MethodGet,
			pathTemplate:   "/api/v1/tickets",
			requestPath:    "/api/v1/tickets/",
			expectedStatus: http.StatusOK,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			op := getOperation(t, spec, tc.pathTemplate, tc.method)

			req := newJSONRequest(t, tc.method, tc.requestPath, tc.body)
			w := httptest.NewRecorder()
			s.ServeHTTP(w, req)

			if w.Code != tc.expectedStatus {
				t.Fatalf("expected status %d, got %d (body=%s)", tc.expectedStatus, w.Code, w.Body.String())
			}

			statusKey := strconv.Itoa(tc.expectedStatus)
			responses := asMap(t, op["responses"], "responses")
			respNode, ok := responses[statusKey]
			if !ok {
				t.Fatalf("OpenAPI missing %s response for %s %s", statusKey, tc.method, tc.pathTemplate)
			}

			schema := resolveResponseSchema(t, spec, asMap(t, respNode, "response node"))
			if schema == nil {
				return
			}

			required := requiredSchemaFields(schema)
			if len(required) == 0 {
				return
			}

			body := decodeJSON(t, w)
			for _, field := range required {
				if _, ok := body[field]; !ok {
					t.Fatalf("response missing required field %q (body=%s)", field, w.Body.String())
				}
			}
		})
	}
}

func loadOpenAPISpec(t *testing.T) map[string]interface{} {
	t.Helper()

	var out map[string]interface{}
	if err := yaml.Unmarshal(apicontract.OpenAPIYAML, &out); err != nil {
		t.Fatalf("parse openapi: %v", err)
	}
	return out
}

func newJSONRequest(t *testing.T, method, path string, body interface{}) *http.Request {
	t.Helper()
	if body == nil {
		return httptest.NewRequest(method, path, nil)
	}
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal request body: %v", err)
	}
	req := httptest.NewRequest(method, path, bytes.NewReader(encoded))
	req.Header.Set("Content-Type", "application/json")
	return req
}

func getOperation(t *testing.T, spec map[string]interface{}, pathTemplate, method string) map[string]interface{} {
	t.Helper()
	paths := asMap(t, spec["paths"], "paths")
	pathNode, ok := paths[pathTemplate]
	if !ok {
		t.Fatalf("path %q not found in OpenAPI", pathTemplate)
	}
	pathMap := asMap(t, pathNode, "path node")
	opNode, ok := pathMap[strings.ToLower(method)]
	if !ok {
		t.Fatalf("method %s not found for path %s in OpenAPI", method, pathTemplate)
	}
	return asMap(t, opNode, "operation")
}

func resolveResponseSchema(t *testing.T, spec map[string]interface{}, response map[string]interface{}) map[string]interface{} {
	t.Helper()
	contentNode, ok := response["content"]
	if !ok {
		return nil
	}
	content := asMap(t, contentNode, "response content")

	applicationJSONNode, ok := content["application/json"]
	if !ok {
		return nil
	}
	applicationJSON := asMap(t, applicationJSONNode, "application/json content")

	schemaNode, ok := applicationJSON["schema"]
	if !ok {
		return nil
	}
	return resolveSchemaRef(t, spec, asMap(t, schemaNode, "schema"))
}

func resolveSchemaRef(t *testing.T, spec map[string]interface{}, schema map[string]interface{}) map[string]interface{} {
	t.Helper()

	ref, ok := schema["$ref"].(string)
	if !ok {
		return schema
	}
	if !strings.HasPrefix(ref, "#/components/schemas/") {
		t.Fatalf("unsupported schema ref: %s", ref)
	}
	name := strings.TrimPrefix(ref, "#/components/schemas/")

	components := asMap(t, spec["components"], "components")
	schemas := asMap(t, components["schemas"], "schemas")
	target, ok := schemas[name]
	if !ok {
		t.Fatalf("schema %q not found", name)
	}
	return asMap(t, target, "schema "+name)
}

func requiredSchemaFields(schema map[string]interface{}) []string {
	raw, ok := schema["required"].([]interface{})
	if !ok {
		return nil
	}

	out := make([]string, 0, len(raw))
	for _, item := range raw {
		if field, ok := item.(string); ok {
			out = append(out, field)
		}
	}
	return out
}

func asMap(t *testing.T, v interface{}, label string) map[string]interface{} {
	t.Helper()
	m, ok := v.(map[string]interface{})
	if !ok {
		t.Fatalf("%s is not a map", label)
	}
	return m
}
