package providers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestWizProviderSchema(t *testing.T) {
	provider := NewWizProvider()
	schema := provider.Schema()

	expectedTables := []string{
		"wiz_cloud_resources",
		"wiz_issues",
		"wiz_vulnerabilities",
		"wiz_security_graph",
		"wiz_cloud_configurations",
		"wiz_attack_paths",
		"wiz_secrets",
		"wiz_identities",
		"wiz_data_findings",
	}

	if len(schema) != len(expectedTables) {
		t.Errorf("expected %d tables, got %d", len(expectedTables), len(schema))
	}

	tableNames := make(map[string]bool)
	for _, table := range schema {
		tableNames[table.Name] = true
	}

	for _, expected := range expectedTables {
		if !tableNames[expected] {
			t.Errorf("missing expected table: %s", expected)
		}
	}
}

func TestWizProviderConfigure(t *testing.T) {
	provider := NewWizProvider()

	config := map[string]interface{}{
		"client_id":     "test-client-id",
		"client_secret": "test-client-secret",
		"api_url":       "https://custom.wiz.io/graphql",
	}

	err := provider.Configure(context.Background(), config)
	if err != nil {
		t.Fatalf("Configure failed: %v", err)
	}

	if provider.clientID != "test-client-id" {
		t.Errorf("expected clientID 'test-client-id', got '%s'", provider.clientID)
	}

	if provider.clientSecret != "test-client-secret" {
		t.Errorf("expected clientSecret 'test-client-secret', got '%s'", provider.clientSecret)
	}

	if provider.apiURL != "https://custom.wiz.io/graphql" {
		t.Errorf("expected apiURL 'https://custom.wiz.io/graphql', got '%s'", provider.apiURL)
	}
}

func TestWizProviderAuthenticate(t *testing.T) {
	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("expected POST, got %s", r.Method)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "test-token",
			"expires_in":   3600,
		})
	}))
	defer authServer.Close()

	provider := NewWizProvider()
	provider.authURL = authServer.URL
	provider.clientID = "test-client"
	provider.clientSecret = "test-secret"

	token, err := provider.authenticate(context.Background())
	if err != nil {
		t.Fatalf("authenticate failed: %v", err)
	}

	if token != "test-token" {
		t.Errorf("expected token 'test-token', got '%s'", token)
	}
}

func TestWizProviderAuthenticateCached(t *testing.T) {
	callCount := 0
	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "test-token",
			"expires_in":   3600,
		})
	}))
	defer authServer.Close()

	provider := NewWizProvider()
	provider.authURL = authServer.URL
	provider.clientID = "test-client"
	provider.clientSecret = "test-secret"

	// First call
	_, err := provider.authenticate(context.Background())
	if err != nil {
		t.Fatalf("first authenticate failed: %v", err)
	}

	// Second call should use cached token
	_, err = provider.authenticate(context.Background())
	if err != nil {
		t.Fatalf("second authenticate failed: %v", err)
	}

	if callCount != 1 {
		t.Errorf("expected 1 auth call (cached), got %d", callCount)
	}
}

func TestWizProviderGraphQLQuery(t *testing.T) {
	apiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Errorf("expected Authorization header 'Bearer test-token'")
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("expected Content-Type 'application/json'")
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"test": "response",
			},
		})
	}))
	defer apiServer.Close()

	provider := NewWizProvider()
	provider.apiURL = apiServer.URL
	provider.token = "test-token"

	body, err := provider.graphQLQuery(context.Background(), "query Test { test }", nil)
	if err != nil {
		t.Fatalf("graphQLQuery failed: %v", err)
	}

	var response map[string]interface{}
	if err := json.Unmarshal(body, &response); err != nil {
		t.Fatalf("unmarshal response failed: %v", err)
	}

	data, ok := response["data"].(map[string]interface{})
	if !ok {
		t.Fatal("expected data field in response")
	}

	if data["test"] != "response" {
		t.Errorf("expected test='response', got '%v'", data["test"])
	}
}

func TestWizProviderGraphQLQueryError(t *testing.T) {
	apiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("unauthorized"))
	}))
	defer apiServer.Close()

	provider := NewWizProvider()
	provider.apiURL = apiServer.URL
	provider.token = "invalid-token"

	_, err := provider.graphQLQuery(context.Background(), "query Test { test }", nil)
	if err == nil {
		t.Fatal("expected error for 401 response")
	}
}

func TestWizProviderSyncCloudResources(t *testing.T) {
	apiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"cloudResources": map[string]interface{}{
					"nodes": []map[string]interface{}{
						{"id": "res-1", "name": "resource-1", "type": "VM"},
						{"id": "res-2", "name": "resource-2", "type": "Bucket"},
					},
					"pageInfo": map[string]interface{}{
						"hasNextPage": false,
						"endCursor":   "",
					},
				},
			},
		})
	}))
	defer apiServer.Close()

	provider := NewWizProvider()
	provider.apiURL = apiServer.URL
	provider.token = "test-token"

	result, err := provider.syncCloudResources(context.Background())
	if err != nil {
		t.Fatalf("syncCloudResources failed: %v", err)
	}

	if result.Name != "wiz_cloud_resources" {
		t.Errorf("expected table name 'wiz_cloud_resources', got '%s'", result.Name)
	}

	if result.Rows != 2 {
		t.Errorf("expected 2 rows, got %d", result.Rows)
	}
}

func TestWizProviderSyncIssues(t *testing.T) {
	apiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"issues": map[string]interface{}{
					"nodes": []map[string]interface{}{
						{"id": "issue-1", "severity": "CRITICAL", "status": "OPEN"},
						{"id": "issue-2", "severity": "HIGH", "status": "OPEN"},
						{"id": "issue-3", "severity": "MEDIUM", "status": "IN_PROGRESS"},
					},
					"pageInfo": map[string]interface{}{
						"hasNextPage": false,
						"endCursor":   "",
					},
				},
			},
		})
	}))
	defer apiServer.Close()

	provider := NewWizProvider()
	provider.apiURL = apiServer.URL
	provider.token = "test-token"

	result, err := provider.syncIssues(context.Background())
	if err != nil {
		t.Fatalf("syncIssues failed: %v", err)
	}

	if result.Name != "wiz_issues" {
		t.Errorf("expected table name 'wiz_issues', got '%s'", result.Name)
	}

	if result.Rows != 3 {
		t.Errorf("expected 3 rows, got %d", result.Rows)
	}
}

func TestWizProviderSyncVulnerabilities(t *testing.T) {
	apiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"vulnerabilityFindings": map[string]interface{}{
					"nodes": []map[string]interface{}{
						{"id": "vuln-1", "name": "CVE-2021-44228", "severity": "CRITICAL"},
					},
					"pageInfo": map[string]interface{}{
						"hasNextPage": false,
						"endCursor":   "",
					},
				},
			},
		})
	}))
	defer apiServer.Close()

	provider := NewWizProvider()
	provider.apiURL = apiServer.URL
	provider.token = "test-token"

	result, err := provider.syncVulnerabilities(context.Background())
	if err != nil {
		t.Fatalf("syncVulnerabilities failed: %v", err)
	}

	if result.Name != "wiz_vulnerabilities" {
		t.Errorf("expected table name 'wiz_vulnerabilities', got '%s'", result.Name)
	}

	if result.Rows != 1 {
		t.Errorf("expected 1 row, got %d", result.Rows)
	}
}

func TestWizProviderSyncSecrets(t *testing.T) {
	apiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"secretFindings": map[string]interface{}{
					"nodes": []map[string]interface{}{
						{"id": "secret-1", "secretType": "AWS_ACCESS_KEY", "isCleartext": true},
						{"id": "secret-2", "secretType": "SSH_PRIVATE_KEY", "isCleartext": true},
					},
					"pageInfo": map[string]interface{}{
						"hasNextPage": false,
						"endCursor":   "",
					},
				},
			},
		})
	}))
	defer apiServer.Close()

	provider := NewWizProvider()
	provider.apiURL = apiServer.URL
	provider.token = "test-token"

	result, err := provider.syncSecrets(context.Background())
	if err != nil {
		t.Fatalf("syncSecrets failed: %v", err)
	}

	if result.Name != "wiz_secrets" {
		t.Errorf("expected table name 'wiz_secrets', got '%s'", result.Name)
	}

	if result.Rows != 2 {
		t.Errorf("expected 2 rows, got %d", result.Rows)
	}
}

func TestWizProviderSyncIdentities(t *testing.T) {
	apiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"cloudIdentities": map[string]interface{}{
					"nodes": []map[string]interface{}{
						{"id": "user-1", "type": "USER", "hasAdminRole": true, "mfaEnabled": false},
						{"id": "sa-1", "type": "SERVICE_ACCOUNT", "hasHighPrivilege": true},
					},
					"pageInfo": map[string]interface{}{
						"hasNextPage": false,
						"endCursor":   "",
					},
				},
			},
		})
	}))
	defer apiServer.Close()

	provider := NewWizProvider()
	provider.apiURL = apiServer.URL
	provider.token = "test-token"

	result, err := provider.syncIdentities(context.Background())
	if err != nil {
		t.Fatalf("syncIdentities failed: %v", err)
	}

	if result.Name != "wiz_identities" {
		t.Errorf("expected table name 'wiz_identities', got '%s'", result.Name)
	}

	if result.Rows != 2 {
		t.Errorf("expected 2 rows, got %d", result.Rows)
	}
}

func TestWizProviderSync(t *testing.T) {
	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "test-token",
			"expires_in":   3600,
		})
	}))
	defer authServer.Close()

	apiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Return empty results for all queries
		json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"cloudResources":        map[string]interface{}{"nodes": []interface{}{}, "pageInfo": map[string]interface{}{"hasNextPage": false}},
				"issues":                map[string]interface{}{"nodes": []interface{}{}, "pageInfo": map[string]interface{}{"hasNextPage": false}},
				"vulnerabilityFindings": map[string]interface{}{"nodes": []interface{}{}, "pageInfo": map[string]interface{}{"hasNextPage": false}},
				"secretFindings":        map[string]interface{}{"nodes": []interface{}{}, "pageInfo": map[string]interface{}{"hasNextPage": false}},
				"cloudIdentities":       map[string]interface{}{"nodes": []interface{}{}, "pageInfo": map[string]interface{}{"hasNextPage": false}},
			},
		})
	}))
	defer apiServer.Close()

	provider := NewWizProvider()
	provider.authURL = authServer.URL
	provider.apiURL = apiServer.URL
	provider.clientID = "test-client"
	provider.clientSecret = "test-secret"

	result, err := provider.Sync(context.Background(), SyncOptions{})
	if err != nil {
		t.Fatalf("Sync failed: %v", err)
	}

	if result.Provider != "wiz" {
		t.Errorf("expected provider 'wiz', got '%s'", result.Provider)
	}

	// Should have synced 5 tables (resources, issues, vulns, secrets, identities)
	if len(result.Tables) != 5 {
		t.Errorf("expected 5 tables synced, got %d", len(result.Tables))
	}
}
