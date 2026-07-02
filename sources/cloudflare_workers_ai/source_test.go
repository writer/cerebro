package cloudflare_workers_ai

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/writer/cerebro/internal/sourcecdk"
)

func TestSourceCheckAndRead(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Fatalf("Authorization"+" = %q", r.Header.Get("Authorization"))
		}
		if r.URL.Path != "/accounts/test-account_id/ai/models/search" {
			t.Fatalf("path = %q", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": []map[string]any{{
				"id":         "@cf/meta/llama-3.1-8b-instruct",
				"name":       "Llama 3.1 8B Instruct",
				"task":       "Text Generation",
				"created_at": "2026-06-01T00:00:00Z",
			}},
			"success": true,
		})
	}))
	defer server.Close()
	cfgValues := map[string]string{"tenant_id": "tenant", "base_url": server.URL, "family": defaultFamily, "token": "test-token", "account_id": "test-account_id", "gateway_id": "test-gateway_id"}
	cfg := sourcecdk.NewConfig(cfgValues)
	if err := source.Check(context.Background(), cfg); err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	pull, err := source.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("events = %d, want 1", len(pull.Events))
	}
	event := pull.Events[0]
	if event.Kind != "cloudflare_workers_ai.model_catalog" {
		t.Fatalf("kind = %q", event.Kind)
	}
	if strings.TrimSpace(event.Id) == "" {
		t.Fatalf("event id is empty: %#v", event)
	}
	if got := event.Attributes["resource_id"]; got != "@cf/meta/llama-3.1-8b-instruct" {
		t.Fatalf("resource_id = %q, want model id", got)
	}
	if got := event.Attributes["resource_name"]; got != "Llama 3.1 8B Instruct" {
		t.Fatalf("resource_name = %q, want model name", got)
	}
	if got := event.Attributes["resource_urn"]; got != "urn:cerebro:tenant:cloudflare_workers_ai_model_catalog:@cf%2Fmeta%2Fllama-3.1-8b-instruct" {
		t.Fatalf("resource_urn = %q, want encoded model URN", got)
	}
	if got := event.Attributes["resource_type"]; got != "model" {
		t.Fatalf("resource_type = %q, want model", got)
	}
	if got := event.Attributes["tenant_id"]; got != "tenant" {
		t.Fatalf("tenant_id = %q, want tenant", got)
	}
}

func TestReadAIGatewaysMapsProviderName(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Path; got != "/accounts/test-account/ai-gateway/gateways" {
			t.Errorf("path = %q, want /accounts/test-account/ai-gateway/gateways", got)
			http.Error(w, "unexpected path", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"result": []map[string]any{{
				"id":         "gateway-1",
				"name":       "production-gateway",
				"type":       "cloudflare_resource",
				"url":        "https://gateway.example.com",
				"status":     "active",
				"created_at": "2026-05-01T00:00:00Z",
				"updated_at": "2026-06-01T00:00:00Z",
			}},
			"success": true,
		})
	}))
	defer server.Close()

	pull, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{
		"account_id": "test-account",
		"base_url":   server.URL,
		"family":     familyAiGateways,
		"gateway_id": "gateway-1",
		"tenant_id":  "tenant",
		"token":      "test-token",
	}), nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("events = %d, want 1", len(pull.Events))
	}
	attrs := pull.Events[0].Attributes
	for attr, want := range map[string]string{
		"deployment_id":   "gateway-1",
		"deployment_name": "production-gateway",
		"resource_type":   "ai_gateway",
		"resource_urn":    "urn:cerebro:tenant:cloudflare_workers_ai_ai_gateways:gateway-1",
		"tenant_id":       "tenant",
	} {
		if got := attrs[attr]; got != want {
			t.Fatalf("%s = %q, want %q", attr, got, want)
		}
	}
}

func TestReadGatewayProviderConfigsDerivesProviderAlias(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Path; got != "/accounts/test-account/ai-gateway/gateways/gateway-1/provider_configs" {
			t.Errorf("path = %q, want /accounts/test-account/ai-gateway/gateways/gateway-1/provider_configs", got)
			http.Error(w, "unexpected path", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"result": []map[string]any{{
				"id":         "provider-config-1",
				"alias":      "openai-production",
				"provider":   "openai",
				"status":     "active",
				"created_at": "2026-05-01T00:00:00Z",
			}},
			"success": true,
		})
	}))
	defer server.Close()

	pull, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{
		"account_id": "test-account",
		"base_url":   server.URL,
		"family":     familyGatewayProviderConfigs,
		"gateway_id": "gateway-1",
		"tenant_id":  "tenant",
		"token":      "test-token",
	}), nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("events = %d, want 1", len(pull.Events))
	}
	attrs := pull.Events[0].Attributes
	for attr, want := range map[string]string{
		"resource_id":   "provider-config-1",
		"resource_name": "openai-production",
		"resource_type": "gateway_provider_config",
		"secret_name":   "openai-production",
		"secret_status": "active",
		"tenant_id":     "tenant",
	} {
		if got := attrs[attr]; got != want {
			t.Fatalf("%s = %q, want %q", attr, got, want)
		}
	}
	if got := attrs["observed_at"]; got != "" {
		t.Fatalf("observed_at = %q, want empty without provider observed/updated timestamp", got)
	}
}

func TestReadGatewayEvaluationsUsesCanonicalResourceType(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Path; got != "/accounts/test-account/ai-gateway/gateways/gateway-1/evaluations" {
			t.Errorf("path = %q, want /accounts/test-account/ai-gateway/gateways/gateway-1/evaluations", got)
			http.Error(w, "unexpected path", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"result": []map[string]any{{
				"id":         "evaluation-1",
				"name":       "Sensitive data policy",
				"status":     "enabled",
				"type":       "prompt_guard",
				"created_at": "2026-05-01T00:00:00Z",
			}},
			"success": true,
		})
	}))
	defer server.Close()

	pull, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{
		"account_id": "test-account",
		"base_url":   server.URL,
		"family":     familyGatewayEvaluations,
		"gateway_id": "gateway-1",
		"tenant_id":  "tenant",
		"token":      "test-token",
	}), nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("events = %d, want 1", len(pull.Events))
	}
	attrs := pull.Events[0].Attributes
	for attr, want := range map[string]string{
		"policy_id":     "evaluation-1",
		"policy_name":   "Sensitive data policy",
		"policy_status": "enabled",
		"policy_type":   "prompt_guard",
		"resource_type": "gateway_evaluation",
		"tenant_id":     "tenant",
	} {
		if got := attrs[attr]; got != want {
			t.Fatalf("%s = %q, want %q", attr, got, want)
		}
	}
	if got := attrs["observed_at"]; got != "" {
		t.Fatalf("observed_at = %q, want empty without provider observed/updated timestamp", got)
	}
}

func TestReadGatewayLogsDefaultsResourceType(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Path; got != "/accounts/test-account/ai-gateway/gateways/gateway-1/logs" {
			t.Errorf("path = %q, want /accounts/test-account/ai-gateway/gateways/gateway-1/logs", got)
			http.Error(w, "unexpected path", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"result": []map[string]any{{
				"id":            "gateway-log-1",
				"event_type":    "ai_gateway.request",
				"actor_id":      "access-user-1",
				"resource_id":   "gateway-1",
				"resource_name": "production-gateway",
				"created_at":    "2026-06-01T00:00:00Z",
			}},
			"success": true,
		})
	}))
	defer server.Close()

	pull, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{
		"account_id": "test-account",
		"base_url":   server.URL,
		"family":     familyGatewayLogs,
		"gateway_id": "gateway-1",
		"tenant_id":  "tenant",
		"token":      "test-token",
	}), nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("events = %d, want 1", len(pull.Events))
	}
	if got := pull.Events[0].Attributes["resource_type"]; got != "ai_gateway" {
		t.Fatalf("resource_type = %q, want static gateway resource type", got)
	}
	if got := pull.Events[0].Attributes["tenant_id"]; got != "tenant" {
		t.Fatalf("tenant_id = %q, want tenant", got)
	}
}

func TestReadVectorizeIndexesDerivesRequiredAttributes(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Path; got != "/accounts/test-account/vectorize/v2/indexes" {
			t.Errorf("path = %q, want /accounts/test-account/vectorize/v2/indexes", got)
			http.Error(w, "unexpected path", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"result": []map[string]any{{
				"name":        "docs-index",
				"dimensions":  1536,
				"metric":      "cosine",
				"description": "Production documentation embeddings",
			}},
			"success": true,
		})
	}))
	defer server.Close()

	pull, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{
		"account_id": "test-account",
		"base_url":   server.URL,
		"family":     familyVectorizeIndexes,
		"tenant_id":  "tenant",
		"token":      "test-token",
	}), nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("events = %d, want 1", len(pull.Events))
	}
	attrs := pull.Events[0].Attributes
	for attr, want := range map[string]string{
		"resource_id":     "docs-index",
		"resource_name":   "docs-index",
		"resource_type":   "vectorize_index",
		"resource_urn":    "urn:cerebro:tenant:cloudflare_workers_ai_vectorize_indexes:docs-index",
		"source_event_id": "docs-index",
		"tenant_id":       "tenant",
	} {
		if got := attrs[attr]; got != want {
			t.Fatalf("%s = %q, want %q", attr, got, want)
		}
	}
}

func TestNewFixtureReplaysEveryRuntimeFamily(t *testing.T) {
	source, err := NewFixture()
	if err != nil {
		t.Fatalf("NewFixture() error = %v", err)
	}

	familyConfigs := map[string]sourcecdk.Config{}
	for _, family := range []string{familyAiGateways, familyGatewayEvaluations, familyGatewayLogs, familyGatewayProviderConfigs, familyModelCatalog, familyVectorizeIndexes} {
		familyConfigs[family] = sourcecdk.NewConfig(map[string]string{
			"account_id": "account-1",
			"family":     family,
			"gateway_id": "gateway-1",
			"tenant_id":  "tenant",
		})
	}
	sourcecdk.RunFixtureSuite(t, context.Background(), sourcecdk.FixtureSuiteOptions{
		Source:          source,
		FamilyConfigs:   familyConfigs,
		RequireDiscover: true,
	})
}

func TestReadProviderUnavailableReturnsProviderError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"errors":[{"message":"service unavailable"}]}`, http.StatusServiceUnavailable)
	}))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()
	_, err = source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{
		"account_id": "account-1",
		"base_url":   server.URL,
		"family":     familyModelCatalog,
		"gateway_id": "gateway-1",
		"tenant_id":  "writer",
		"token":      "token-1",
	}), nil)
	if err == nil {
		t.Fatal("Read() error = nil, want provider error")
	}
	if got := err.Error(); !strings.Contains(got, "cloudflare_workers_ai API returned 503") {
		t.Fatalf("Read() error = %q, want provider status", got)
	}
}
