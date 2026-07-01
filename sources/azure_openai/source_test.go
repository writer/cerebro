package azure_openai

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/sourcecdk"
)

func TestSourceCheckAndReadDeploymentsUsesARMValueAndHeaders(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()

	requests := make([]*http.Request, 0, 3)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.Clone(r.Context()))
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Fatalf("Authorization = %q", r.Header.Get("Authorization"))
		}
		if r.URL.Path != "/subscriptions/sub-0000/resourceGroups/rg-ai/providers/Microsoft.CognitiveServices/accounts/acct-openai/deployments" {
			t.Fatalf("path = %q", r.URL.Path)
		}
		if r.URL.Query().Get("api-version") != "2024-10-01" {
			t.Fatalf("api-version = %q", r.URL.Query().Get("api-version"))
		}
		if r.URL.Query().Has("limit") || r.URL.Query().Has("per_page") {
			t.Fatalf("unexpected page-size query: %q", r.URL.RawQuery)
		}
		writeJSON(t, w, map[string]any{
			"value": []map[string]any{{
				"id":   "/subscriptions/sub-0000/resourceGroups/rg-ai/providers/Microsoft.CognitiveServices/accounts/acct-openai/deployments/gpt-4o-prod",
				"name": "gpt-4o-prod",
				"type": "Microsoft.CognitiveServices/accounts/deployments",
				"sku": map[string]any{
					"name":     "Standard",
					"capacity": 3,
				},
				"properties": map[string]any{
					"model": map[string]any{
						"format":  "OpenAI",
						"name":    "gpt-4o",
						"version": "2024-08-06",
					},
					"provisioningState": "Succeeded",
				},
				"systemData": map[string]any{
					"createdAt":      "2026-06-01T00:00:00Z",
					"lastModifiedAt": "2026-06-02T00:00:00Z",
				},
			}},
			"nextLink": "http://" + r.Host + r.URL.Path + "?api-version=2024-10-01&skipToken=deployments-page-2",
		})
	}))
	defer server.Close()

	cfg := testConfig(server.URL, map[string]string{"family": familyDeployments})
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
	if event.Kind != "azure_openai.deployments" {
		t.Fatalf("kind = %q", event.Kind)
	}
	if strings.TrimSpace(event.Id) == "" {
		t.Fatalf("event id is empty: %#v", event)
	}
	if event.Attributes["deployment_status"] != "Succeeded" {
		t.Fatalf("deployment_status = %q", event.Attributes["deployment_status"])
	}
	if event.Attributes["resource_type"] != "Microsoft.CognitiveServices/accounts/deployments" {
		t.Fatalf("resource_type = %q", event.Attributes["resource_type"])
	}
	if !strings.Contains(event.Attributes["resource_urn"], "azure_openai_deployments") {
		t.Fatalf("resource_urn = %q, want synthesized deployment URN", event.Attributes["resource_urn"])
	}
	if got := event.GetOccurredAt().AsTime().UTC().Format(time.RFC3339); got != "2026-06-02T00:00:00Z" {
		t.Fatalf("occurred_at = %q, want provider lastModifiedAt", got)
	}
	if !strings.Contains(pull.NextCursor.GetOpaque(), "skipToken=deployments-page-2") {
		t.Fatalf("NextCursor = %q", pull.NextCursor.GetOpaque())
	}
	if len(requests) != 3 {
		t.Fatalf("requests = %d, want Check health, Check family, and Read", len(requests))
	}
}

func TestSourceReadFollowsAzureNextLink(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()

	requests := make([]*http.Request, 0, 2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.Clone(r.Context()))
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Fatalf("Authorization = %q", r.Header.Get("Authorization"))
		}
		if r.URL.Path != "/subscriptions/sub-0000/resourceGroups/rg-ai/providers/Microsoft.CognitiveServices/accounts/acct-openai/raiPolicies" {
			t.Fatalf("path = %q", r.URL.Path)
		}
		switch r.URL.Query().Get("skipToken") {
		case "":
			writeJSON(t, w, map[string]any{
				"value":    []map[string]any{raiPolicyRecord("content-filter-prod", "DefaultV2", "Blocking")},
				"nextLink": serverNextLink(r, "page-2"),
			})
		case "page-2":
			writeJSON(t, w, map[string]any{
				"value": []map[string]any{raiPolicyRecord("content-filter-shadow", "Microsoft.Default", "Asynchronous_filter")},
			})
		default:
			t.Fatalf("skipToken = %q", r.URL.Query().Get("skipToken"))
		}
	}))
	defer server.Close()

	cfg := testConfig(server.URL, map[string]string{"family": familyRaiPolicies})
	first, err := source.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Read(first) error = %v", err)
	}
	if len(first.Events) != 1 {
		t.Fatalf("first events = %d, want 1", len(first.Events))
	}
	if first.Events[0].Attributes["policy_status"] != "Blocking" {
		t.Fatalf("first policy_status = %q", first.Events[0].Attributes["policy_status"])
	}
	if first.NextCursor.GetOpaque() == "" {
		t.Fatalf("first NextCursor is empty")
	}

	second, err := source.Read(context.Background(), cfg, first.NextCursor)
	if err != nil {
		t.Fatalf("Read(second) error = %v", err)
	}
	if len(second.Events) != 1 {
		t.Fatalf("second events = %d, want 1", len(second.Events))
	}
	if second.Events[0].Attributes["policy_status"] != "Asynchronous_filter" {
		t.Fatalf("second policy_status = %q", second.Events[0].Attributes["policy_status"])
	}
	if len(requests) != 2 || requests[1].URL.Query().Get("skipToken") != "page-2" {
		t.Fatalf("requests = %#v, want second request from nextLink", requests)
	}
}

func TestSourceReadPrivateEndpointConnectionsUsesARMValue(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Fatalf("Authorization = %q", r.Header.Get("Authorization"))
		}
		if r.URL.Path != "/subscriptions/sub-0000/resourceGroups/rg-ai/providers/Microsoft.CognitiveServices/accounts/acct-openai/privateEndpointConnections" {
			t.Fatalf("path = %q", r.URL.Path)
		}
		writeJSON(t, w, map[string]any{
			"value": []map[string]any{{
				"id":   "/subscriptions/sub-0000/resourceGroups/rg-ai/providers/Microsoft.CognitiveServices/accounts/acct-openai/privateEndpointConnections/pec-prod",
				"name": "pec-prod",
				"type": "Microsoft.CognitiveServices/accounts/privateEndpointConnections",
				"properties": map[string]any{
					"privateEndpoint": map[string]any{
						"id": "/subscriptions/sub-0000/resourceGroups/rg-network/providers/Microsoft.Network/privateEndpoints/pe-openai-prod",
					},
					"privateLinkServiceConnectionState": map[string]any{
						"status":          "Approved",
						"description":     "Approved for production traffic",
						"actionsRequired": "None",
					},
				},
			}},
		})
	}))
	defer server.Close()

	cfg := testConfig(server.URL, map[string]string{"family": familyPrivateEndpointConnections})
	pull, err := source.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("events = %d, want 1", len(pull.Events))
	}
	attrs := pull.Events[0].Attributes
	if attrs["resource_type"] != "Microsoft.CognitiveServices/accounts/privateEndpointConnections" {
		t.Fatalf("resource_type = %q", attrs["resource_type"])
	}
	if attrs["private_link_service_connection_status"] != "Approved" {
		t.Fatalf("private_link_service_connection_status = %q", attrs["private_link_service_connection_status"])
	}
	if !strings.Contains(attrs["private_endpoint_id"], "/Microsoft.Network/privateEndpoints/pe-openai-prod") {
		t.Fatalf("private_endpoint_id = %q", attrs["private_endpoint_id"])
	}
}

func TestReadProviderUnavailableReturnsProviderError(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"error":{"message":"service unavailable"}}`, http.StatusServiceUnavailable)
	}))
	defer server.Close()

	_, err = source.Read(context.Background(), testConfig(server.URL, map[string]string{"family": familyDeployments}), nil)
	if err == nil {
		t.Fatal("Read() error = nil, want provider error")
	}
	if got := err.Error(); !strings.Contains(got, "azure_openai API returned 503") {
		t.Fatalf("Read() error = %q, want provider status", got)
	}
}

func TestSourceReadsEveryAzureManagementFamily(t *testing.T) {
	tests := []struct {
		family string
		path   string
		kind   string
		record map[string]any
		attr   string
		want   string
	}{
		{
			family: familyDeployments,
			path:   "/subscriptions/sub-0000/resourceGroups/rg-ai/providers/Microsoft.CognitiveServices/accounts/acct-openai/deployments",
			kind:   "azure_openai.deployments",
			record: deploymentRecord(),
			attr:   "deployment_status",
			want:   "Succeeded",
		},
		{
			family: familyModelCatalog,
			path:   "/subscriptions/sub-0000/providers/Microsoft.CognitiveServices/locations/eastus/models",
			kind:   "azure_openai.model_catalog",
			record: azureModelRecord(),
			attr:   "resource_id",
			want:   "gpt-4o",
		},
		{
			family: familyRaiPolicies,
			path:   "/subscriptions/sub-0000/resourceGroups/rg-ai/providers/Microsoft.CognitiveServices/accounts/acct-openai/raiPolicies",
			kind:   "azure_openai.rai_policies",
			record: raiPolicyRecord("content-filter-prod", "DefaultV2", "Blocking"),
			attr:   "policy_status",
			want:   "Blocking",
		},
		{
			family: familyRaiBlocklists,
			path:   "/subscriptions/sub-0000/resourceGroups/rg-ai/providers/Microsoft.CognitiveServices/accounts/acct-openai/raiBlocklists",
			kind:   "azure_openai.rai_blocklists",
			record: raiBlocklistRecord(),
			attr:   "policy_description",
			want:   "Custom moderation terms",
		},
		{
			family: familyPrivateEndpointConnections,
			path:   "/subscriptions/sub-0000/resourceGroups/rg-ai/providers/Microsoft.CognitiveServices/accounts/acct-openai/privateEndpointConnections",
			kind:   "azure_openai.private_endpoint_connections",
			record: privateEndpointConnectionRecord(),
			attr:   "private_link_service_connection_status",
			want:   "Approved",
		},
	}
	for _, tt := range tests {
		t.Run(tt.family, func(t *testing.T) {
			source, err := New()
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			source.allowLoopbackForTest()
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "Bearer test-token" {
					t.Fatalf("Authorization = %q", r.Header.Get("Authorization"))
				}
				if r.URL.Path != tt.path {
					t.Fatalf("path = %q, want %q", r.URL.Path, tt.path)
				}
				if r.URL.Query().Get("api-version") != "2024-10-01" {
					t.Fatalf("api-version = %q", r.URL.Query().Get("api-version"))
				}
				writeJSON(t, w, map[string]any{"value": []map[string]any{tt.record}})
			}))
			defer server.Close()

			pull, err := source.Read(context.Background(), testConfig(server.URL, map[string]string{"family": tt.family}), nil)
			if err != nil {
				t.Fatalf("Read() error = %v", err)
			}
			if len(pull.Events) != 1 {
				t.Fatalf("events = %d, want 1", len(pull.Events))
			}
			event := pull.Events[0]
			if event.Kind != tt.kind {
				t.Fatalf("kind = %q, want %q", event.Kind, tt.kind)
			}
			if got := event.Attributes[tt.attr]; got != tt.want {
				t.Fatalf("%s = %q, want %q", tt.attr, got, tt.want)
			}
			if strings.TrimSpace(event.Attributes["resource_urn"]) == "" {
				t.Fatalf("resource_urn is empty for %s: %#v", tt.family, event.Attributes)
			}
			if tt.family != familyModelCatalog {
				if got := event.GetOccurredAt().AsTime().UTC().Format(time.RFC3339); got != "2026-06-02T00:00:00Z" {
					t.Fatalf("occurred_at = %q, want provider systemData timestamp", got)
				}
			}
		})
	}
}

func TestSourceConfigValidation(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("unexpected request to %s", r.URL.String())
	}))
	defer server.Close()

	tests := []struct {
		name   string
		family string
		remove string
	}{
		{name: "subscription", family: familyDeployments, remove: "subscription_id"},
		{name: "resource group", family: familyDeployments, remove: "resource_group"},
		{name: "account", family: familyDeployments, remove: "account_name"},
		{name: "location", family: familyModelCatalog, remove: "location"},
		{name: "token", family: familyDeployments, remove: "token"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := testConfig(server.URL, map[string]string{"family": tt.family, tt.remove: ""})
			_, err := source.Read(context.Background(), cfg, nil)
			if !errors.Is(err, sourcecdk.ErrInvalidConfig) {
				t.Fatalf("Read() error = %v, want ErrInvalidConfig", err)
			}
		})
	}
}

func testConfig(baseURL string, overrides map[string]string) sourcecdk.Config {
	values := map[string]string{
		"tenant_id":       "tenant",
		"base_url":        baseURL,
		"family":          defaultFamily,
		"token":           "test-token",
		"account_name":    "acct-openai",
		"location":        "eastus",
		"resource_group":  "rg-ai",
		"subscription_id": "sub-0000",
	}
	for key, value := range overrides {
		values[key] = value
	}
	return sourcecdk.NewConfig(values)
}

func deploymentRecord() map[string]any {
	return map[string]any{
		"id":   "/subscriptions/sub-0000/resourceGroups/rg-ai/providers/Microsoft.CognitiveServices/accounts/acct-openai/deployments/gpt-4o-prod",
		"name": "gpt-4o-prod",
		"type": "Microsoft.CognitiveServices/accounts/deployments",
		"sku": map[string]any{
			"name":     "Standard",
			"capacity": 3,
		},
		"properties": map[string]any{
			"model": map[string]any{
				"format":  "OpenAI",
				"name":    "gpt-4o",
				"version": "2024-08-06",
			},
			"provisioningState": "Succeeded",
		},
		"systemData": map[string]any{
			"createdAt":      "2026-06-01T00:00:00Z",
			"lastModifiedAt": "2026-06-02T00:00:00Z",
		},
	}
}

func azureModelRecord() map[string]any {
	return map[string]any{
		"kind":    "OpenAI",
		"skuName": "GlobalStandard",
		"model": map[string]any{
			"format":          "OpenAI",
			"name":            "gpt-4o",
			"version":         "2024-08-06",
			"publisher":       "OpenAI",
			"source":          "AzureOpenAI",
			"lifecycleStatus": "GenerallyAvailable",
			"capabilities": map[string]any{
				"assistants":     "true",
				"chatCompletion": "true",
			},
		},
	}
}

func raiPolicyRecord(name string, basePolicyName string, mode string) map[string]any {
	return map[string]any{
		"id":   "/subscriptions/sub-0000/resourceGroups/rg-ai/providers/Microsoft.CognitiveServices/accounts/acct-openai/raiPolicies/" + name,
		"name": name,
		"type": "Microsoft.CognitiveServices/accounts/raiPolicies",
		"properties": map[string]any{
			"basePolicyName": basePolicyName,
			"mode":           mode,
			"contentFilters": []map[string]any{{
				"name":              "Hate",
				"blocking":          true,
				"enabled":           true,
				"severityThreshold": "Medium",
				"source":            "Prompt",
			}},
		},
		"systemData": map[string]any{
			"createdAt":      "2026-06-01T00:00:00Z",
			"lastModifiedAt": "2026-06-02T00:00:00Z",
		},
	}
}

func raiBlocklistRecord() map[string]any {
	return map[string]any{
		"id":   "/subscriptions/sub-0000/resourceGroups/rg-ai/providers/Microsoft.CognitiveServices/accounts/acct-openai/raiBlocklists/customer-terms",
		"name": "customer-terms",
		"type": "Microsoft.CognitiveServices/accounts/raiBlocklists",
		"properties": map[string]any{
			"description":       "Custom moderation terms",
			"provisioningState": "Succeeded",
		},
		"systemData": map[string]any{
			"createdAt":      "2026-06-01T00:00:00Z",
			"lastModifiedAt": "2026-06-02T00:00:00Z",
		},
	}
}

func privateEndpointConnectionRecord() map[string]any {
	return map[string]any{
		"id":   "/subscriptions/sub-0000/resourceGroups/rg-ai/providers/Microsoft.CognitiveServices/accounts/acct-openai/privateEndpointConnections/pec-prod",
		"name": "pec-prod",
		"type": "Microsoft.CognitiveServices/accounts/privateEndpointConnections",
		"properties": map[string]any{
			"privateEndpoint": map[string]any{
				"id": "/subscriptions/sub-0000/resourceGroups/rg-network/providers/Microsoft.Network/privateEndpoints/pe-openai-prod",
			},
			"privateLinkServiceConnectionState": map[string]any{
				"status":          "Approved",
				"description":     "Approved for production traffic",
				"actionsRequired": "None",
			},
		},
		"systemData": map[string]any{
			"createdAt":      "2026-06-01T00:00:00Z",
			"lastModifiedAt": "2026-06-02T00:00:00Z",
		},
	}
}

func serverNextLink(r *http.Request, skipToken string) string {
	return "http://" + r.Host + r.URL.Path + "?api-version=2024-10-01&skipToken=" + skipToken
}

func writeJSON(t *testing.T, w http.ResponseWriter, body any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(body); err != nil {
		t.Fatalf("encode response: %v", err)
	}
}
