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
