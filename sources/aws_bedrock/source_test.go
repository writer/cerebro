package aws_bedrock

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
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "AWS4-HMAC-SHA256 ") {
			t.Fatalf("Authorization"+" = %q", auth)
		}
		if !strings.Contains(auth, "Credential=test-access-key/") {
			t.Fatalf("Authorization"+" missing credential scope: %q", auth)
		}
		if r.URL.Path != "/foundation-models" {
			t.Fatalf("path = %q", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"modelSummaries": []map[string]any{{
			"modelArn":         "arn:aws:bedrock:us-east-1::foundation-model/amazon.titan-text-express-v1",
			"modelId":          "amazon.titan-text-express-v1",
			"modelName":        "Amazon Titan Text Express",
			"providerName":     "Amazon",
			"inputModalities":  []string{"TEXT"},
			"outputModalities": []string{"TEXT"},
		}}})
	}))
	defer server.Close()
	cfgValues := map[string]string{"tenant_id": "tenant", "base_url": server.URL, "family": defaultFamily, "access_key": "test-access-key", "secret_key": "test-secret-key", "region": "test-region", "service": "test-service"}
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
	if event.Kind != "aws_bedrock.foundation_models" {
		t.Fatalf("kind = %q", event.Kind)
	}
	if strings.TrimSpace(event.Id) == "" {
		t.Fatalf("event id is empty: %#v", event)
	}
	if got := event.Attributes["resource_id"]; got != "amazon.titan-text-express-v1" {
		t.Fatalf("resource_id = %q, want amazon.titan-text-express-v1", got)
	}
	for attr, want := range map[string]string{
		"source_event_id": "amazon.titan-text-express-v1",
		"resource_urn":    "urn:cerebro:tenant:aws_bedrock_foundation_models:amazon.titan-text-express-v1",
		"resource_type":   "foundation_model",
	} {
		if got := event.Attributes[attr]; got != want {
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
	for _, family := range []string{
		familyCustomModels,
		familyFoundationModels,
		familyGuardrails,
		familyModelCustomizationJobs,
		familyProvisionedModelThroughputs,
	} {
		familyConfigs[family] = sourcecdk.NewConfig(map[string]string{
			"family":    family,
			"tenant_id": "tenant",
		})
	}
	sourcecdk.RunFixtureSuite(t, context.Background(), sourcecdk.FixtureSuiteOptions{
		Source:          source,
		FamilyConfigs:   familyConfigs,
		RequireDiscover: true,
	})
}

func TestReadProviderUnavailableReturnsProviderError(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"message":"temporarily unavailable"}`, http.StatusServiceUnavailable)
	}))
	defer server.Close()

	_, err = source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{
		"access_key": "test-access-key",
		"base_url":   server.URL,
		"family":     defaultFamily,
		"region":     "test-region",
		"secret_key": "test-secret-key",
		"service":    "test-service",
		"tenant_id":  "tenant",
	}), nil)
	if err == nil {
		t.Fatal("Read() error = nil, want provider error")
	}
	if got := err.Error(); !strings.Contains(got, "aws_bedrock API returned 503") {
		t.Fatalf("Read() error = %q, want provider status", got)
	}
}
