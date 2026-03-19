package client

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestBackfillRelationshipIDs_SendsBatchSizeAndParsesResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/api/v1/sync/backfill-relationships" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}

		var req map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode request body: %v", err)
		}
		if req["batch_size"] != float64(250) {
			t.Fatalf("expected batch_size=250, got %#v", req["batch_size"])
		}

		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"scanned": 10,
			"updated": 4,
			"deleted": 3,
			"skipped": 3,
		})
	}))
	defer server.Close()

	c, err := New(Config{
		BaseURL: server.URL,
		APIKey:  "test-key",
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	stats, err := c.BackfillRelationshipIDs(context.Background(), 250)
	if err != nil {
		t.Fatalf("BackfillRelationshipIDs returned error: %v", err)
	}
	if stats.Scanned != 10 || stats.Updated != 4 || stats.Deleted != 3 || stats.Skipped != 3 {
		t.Fatalf("unexpected stats: %+v", stats)
	}
}

func TestBackfillRelationshipIDs_ZeroBatchUsesDefaultServerBehavior(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/sync/backfill-relationships" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}

		var req map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
			t.Fatalf("decode request body: %v", err)
		}
		if len(req) != 0 {
			t.Fatalf("expected empty request body for default batch size, got %#v", req)
		}

		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"scanned": 1,
			"updated": 1,
			"deleted": 0,
			"skipped": 0,
		})
	}))
	defer server.Close()

	c, err := New(Config{
		BaseURL: server.URL,
		APIKey:  "test-key",
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	stats, err := c.BackfillRelationshipIDs(context.Background(), 0)
	if err != nil {
		t.Fatalf("BackfillRelationshipIDs returned error: %v", err)
	}
	if stats.Scanned != 1 || stats.Updated != 1 {
		t.Fatalf("unexpected stats: %+v", stats)
	}
}

func TestRunAzureSync_SendsRequestAndParsesResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/api/v1/sync/azure" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}

		var req map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode request body: %v", err)
		}
		if req["subscription"] != "sub-123" {
			t.Fatalf("expected subscription sub-123, got %#v", req["subscription"])
		}
		if req["concurrency"] != float64(9) {
			t.Fatalf("expected concurrency=9, got %#v", req["concurrency"])
		}
		if req["validate"] != true {
			t.Fatalf("expected validate=true, got %#v", req["validate"])
		}
		tables, ok := req["tables"].([]interface{})
		if !ok || len(tables) != 2 || tables[0] != "azure_vm_instances" || tables[1] != "azure_storage_accounts" {
			t.Fatalf("unexpected tables payload: %#v", req["tables"])
		}

		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"provider": "azure",
			"validate": true,
			"results": []map[string]interface{}{
				{
					"table":    "azure_vm_instances",
					"synced":   4,
					"errors":   0,
					"duration": float64(1000000000),
				},
			},
		})
	}))
	defer server.Close()

	c, err := New(Config{
		BaseURL: server.URL,
		APIKey:  "test-key",
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	resp, err := c.RunAzureSync(context.Background(), AzureSyncRequest{
		Subscription: " sub-123 ",
		Concurrency:  9,
		Tables:       []string{"azure_vm_instances", "azure_storage_accounts"},
		Validate:     true,
	})
	if err != nil {
		t.Fatalf("RunAzureSync returned error: %v", err)
	}
	if resp.Provider != "azure" || !resp.Validate || len(resp.Results) != 1 {
		t.Fatalf("unexpected response: %+v", resp)
	}
	if resp.Results[0].Table != "azure_vm_instances" || resp.Results[0].Synced != 4 {
		t.Fatalf("unexpected first result: %+v", resp.Results[0])
	}
}

func TestRunAzureSync_EmptyRequestBodyForDefaultBehavior(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/sync/azure" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}

		var req map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
			t.Fatalf("decode request body: %v", err)
		}
		if len(req) != 0 {
			t.Fatalf("expected empty request body, got %#v", req)
		}

		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"provider": "azure",
			"validate": false,
			"results":  []map[string]interface{}{},
		})
	}))
	defer server.Close()

	c, err := New(Config{
		BaseURL: server.URL,
		APIKey:  "test-key",
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	resp, err := c.RunAzureSync(context.Background(), AzureSyncRequest{})
	if err != nil {
		t.Fatalf("RunAzureSync returned error: %v", err)
	}
	if resp.Provider != "azure" || resp.Validate {
		t.Fatalf("unexpected response: %+v", resp)
	}
}

func TestRunAzureSync_SendsManagementGroupAndSubscriptionConcurrency(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/sync/azure" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}

		var req map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode request body: %v", err)
		}
		if req["management_group"] != "mg-platform" {
			t.Fatalf("expected management_group mg-platform, got %#v", req["management_group"])
		}
		if req["subscription_concurrency"] != float64(6) {
			t.Fatalf("expected subscription_concurrency=6, got %#v", req["subscription_concurrency"])
		}
		if _, ok := req["subscription"]; ok {
			t.Fatalf("did not expect single subscription field in management-group request: %#v", req)
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"provider": "azure",
			"validate": false,
			"results":  []map[string]interface{}{},
		})
	}))
	defer server.Close()

	c, err := New(Config{
		BaseURL: server.URL,
		APIKey:  "test-key",
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	resp, err := c.RunAzureSync(context.Background(), AzureSyncRequest{
		ManagementGroup:         " mg-platform ",
		SubscriptionConcurrency: 6,
	})
	if err != nil {
		t.Fatalf("RunAzureSync returned error: %v", err)
	}
	if resp.Provider != "azure" {
		t.Fatalf("unexpected response: %+v", resp)
	}
}

func TestRunAWSSync_SendsRequestAndParsesResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/api/v1/sync/aws" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}

		var req map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode request body: %v", err)
		}
		if req["profile"] != "prod-profile" {
			t.Fatalf("expected profile prod-profile, got %#v", req["profile"])
		}
		if req["region"] != "us-west-2" {
			t.Fatalf("expected region us-west-2, got %#v", req["region"])
		}
		if req["multi_region"] != true {
			t.Fatalf("expected multi_region=true, got %#v", req["multi_region"])
		}
		if req["concurrency"] != float64(11) {
			t.Fatalf("expected concurrency=11, got %#v", req["concurrency"])
		}
		if req["validate"] != true {
			t.Fatalf("expected validate=true, got %#v", req["validate"])
		}
		if req["permission_usage_lookback_days"] != float64(270) {
			t.Fatalf("expected permission_usage_lookback_days=270, got %#v", req["permission_usage_lookback_days"])
		}
		if req["permission_removal_threshold_days"] != float64(180) {
			t.Fatalf("expected permission_removal_threshold_days=180, got %#v", req["permission_removal_threshold_days"])
		}
		include, ok := req["aws_identity_center_permission_sets_include"].([]interface{})
		if !ok || len(include) != 2 || include[0] != "Admin" || include[1] != "arn:aws:sso:::permissionSet/ssoins-123/ps-123" {
			t.Fatalf("unexpected aws_identity_center_permission_sets_include payload: %#v", req["aws_identity_center_permission_sets_include"])
		}
		exclude, ok := req["aws_identity_center_permission_sets_exclude"].([]interface{})
		if !ok || len(exclude) != 1 || exclude[0] != "ReadOnly" {
			t.Fatalf("unexpected aws_identity_center_permission_sets_exclude payload: %#v", req["aws_identity_center_permission_sets_exclude"])
		}
		tables, ok := req["tables"].([]interface{})
		if !ok || len(tables) != 2 || tables[0] != "aws_iam_users" || tables[1] != "aws_s3_buckets" {
			t.Fatalf("unexpected tables payload: %#v", req["tables"])
		}

		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"provider":                     "aws",
			"validate":                     true,
			"relationships_extracted":      14,
			"relationships_skipped_reason": "",
			"results": []map[string]interface{}{
				{
					"table":    "aws_iam_users",
					"synced":   7,
					"errors":   0,
					"duration": float64(3000000000),
				},
			},
		})
	}))
	defer server.Close()

	c, err := New(Config{
		BaseURL: server.URL,
		APIKey:  "test-key",
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	resp, err := c.RunAWSSync(context.Background(), AWSSyncRequest{
		Profile:                                " prod-profile ",
		Region:                                 " us-west-2 ",
		MultiRegion:                            true,
		Concurrency:                            11,
		Tables:                                 []string{"aws_iam_users", "aws_s3_buckets"},
		Validate:                               true,
		PermissionUsageLookbackDays:            270,
		PermissionRemovalThresholdDays:         180,
		AWSIdentityCenterPermissionSetsInclude: []string{" Admin ", "arn:aws:sso:::permissionSet/ssoins-123/ps-123"},
		AWSIdentityCenterPermissionSetsExclude: []string{" ReadOnly "},
	})
	if err != nil {
		t.Fatalf("RunAWSSync returned error: %v", err)
	}
	if resp.Provider != "aws" || !resp.Validate || len(resp.Results) != 1 {
		t.Fatalf("unexpected response: %+v", resp)
	}
	if resp.Results[0].Table != "aws_iam_users" || resp.Results[0].Synced != 7 {
		t.Fatalf("unexpected first result: %+v", resp.Results[0])
	}
	if resp.RelationshipsExtracted != 14 {
		t.Fatalf("unexpected relationship count: %d", resp.RelationshipsExtracted)
	}
}

func TestRunAWSSync_EmptyRequestBodyForDefaultBehavior(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/sync/aws" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}

		var req map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
			t.Fatalf("decode request body: %v", err)
		}
		if len(req) != 0 {
			t.Fatalf("expected empty request body, got %#v", req)
		}

		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"provider": "aws",
			"validate": false,
			"results":  []map[string]interface{}{},
		})
	}))
	defer server.Close()

	c, err := New(Config{
		BaseURL: server.URL,
		APIKey:  "test-key",
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	resp, err := c.RunAWSSync(context.Background(), AWSSyncRequest{})
	if err != nil {
		t.Fatalf("RunAWSSync returned error: %v", err)
	}
	if resp.Provider != "aws" || resp.Validate {
		t.Fatalf("unexpected response: %+v", resp)
	}
}

func TestRunAWSOrgSync_SendsRequestAndParsesResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/api/v1/sync/aws-org" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}

		var req map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode request body: %v", err)
		}
		if req["profile"] != "prod-profile" {
			t.Fatalf("expected profile prod-profile, got %#v", req["profile"])
		}
		if req["region"] != "us-west-2" {
			t.Fatalf("expected region us-west-2, got %#v", req["region"])
		}
		if req["multi_region"] != true {
			t.Fatalf("expected multi_region=true, got %#v", req["multi_region"])
		}
		if req["concurrency"] != float64(9) {
			t.Fatalf("expected concurrency=9, got %#v", req["concurrency"])
		}
		if req["validate"] != true {
			t.Fatalf("expected validate=true, got %#v", req["validate"])
		}
		if req["org_role"] != "OrganizationAccountAccessRole" {
			t.Fatalf("expected org_role OrganizationAccountAccessRole, got %#v", req["org_role"])
		}
		if req["account_concurrency"] != float64(3) {
			t.Fatalf("expected account_concurrency=3, got %#v", req["account_concurrency"])
		}
		if req["permission_usage_lookback_days"] != float64(365) {
			t.Fatalf("expected permission_usage_lookback_days=365, got %#v", req["permission_usage_lookback_days"])
		}
		if req["permission_removal_threshold_days"] != float64(210) {
			t.Fatalf("expected permission_removal_threshold_days=210, got %#v", req["permission_removal_threshold_days"])
		}
		includePS, ok := req["aws_identity_center_permission_sets_include"].([]interface{})
		if !ok || len(includePS) != 1 || includePS[0] != "Admin" {
			t.Fatalf("unexpected aws_identity_center_permission_sets_include payload: %#v", req["aws_identity_center_permission_sets_include"])
		}
		excludePS, ok := req["aws_identity_center_permission_sets_exclude"].([]interface{})
		if !ok || len(excludePS) != 1 || excludePS[0] != "Billing" {
			t.Fatalf("unexpected aws_identity_center_permission_sets_exclude payload: %#v", req["aws_identity_center_permission_sets_exclude"])
		}
		includeAccounts, ok := req["include_accounts"].([]interface{})
		if !ok || len(includeAccounts) != 2 || includeAccounts[0] != "111111111111" || includeAccounts[1] != "222222222222" {
			t.Fatalf("unexpected include_accounts payload: %#v", req["include_accounts"])
		}
		excludeAccounts, ok := req["exclude_accounts"].([]interface{})
		if !ok || len(excludeAccounts) != 1 || excludeAccounts[0] != "333333333333" {
			t.Fatalf("unexpected exclude_accounts payload: %#v", req["exclude_accounts"])
		}
		tables, ok := req["tables"].([]interface{})
		if !ok || len(tables) != 2 || tables[0] != "aws_iam_users" || tables[1] != "aws_s3_buckets" {
			t.Fatalf("unexpected tables payload: %#v", req["tables"])
		}

		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"provider": "aws_org",
			"validate": true,
			"results": []map[string]interface{}{
				{
					"table":    "aws_iam_users",
					"synced":   12,
					"errors":   0,
					"duration": float64(1000000000),
				},
			},
			"account_errors": []string{"account 333333333333: access denied"},
		})
	}))
	defer server.Close()

	c, err := New(Config{
		BaseURL: server.URL,
		APIKey:  "test-key",
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	resp, err := c.RunAWSOrgSync(context.Background(), AWSOrgSyncRequest{
		Profile:                                " prod-profile ",
		Region:                                 " us-west-2 ",
		MultiRegion:                            true,
		Concurrency:                            9,
		Tables:                                 []string{"aws_iam_users", "aws_s3_buckets"},
		Validate:                               true,
		OrgRole:                                " OrganizationAccountAccessRole ",
		IncludeAccounts:                        []string{" 111111111111 ", "222222222222"},
		ExcludeAccounts:                        []string{"333333333333"},
		AccountConcurrency:                     3,
		PermissionUsageLookbackDays:            365,
		PermissionRemovalThresholdDays:         210,
		AWSIdentityCenterPermissionSetsInclude: []string{" Admin "},
		AWSIdentityCenterPermissionSetsExclude: []string{" Billing "},
	})
	if err != nil {
		t.Fatalf("RunAWSOrgSync returned error: %v", err)
	}
	if resp.Provider != "aws_org" || !resp.Validate || len(resp.Results) != 1 {
		t.Fatalf("unexpected response: %+v", resp)
	}
	if resp.Results[0].Table != "aws_iam_users" || resp.Results[0].Synced != 12 {
		t.Fatalf("unexpected first result: %+v", resp.Results[0])
	}
	if len(resp.AccountErrors) != 1 || resp.AccountErrors[0] != "account 333333333333: access denied" {
		t.Fatalf("unexpected account errors: %#v", resp.AccountErrors)
	}
}

func TestRunAWSOrgSync_EmptyRequestBodyForDefaultBehavior(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/sync/aws-org" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}

		var req map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
			t.Fatalf("decode request body: %v", err)
		}
		if len(req) != 0 {
			t.Fatalf("expected empty request body, got %#v", req)
		}

		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"provider": "aws_org",
			"validate": false,
			"results":  []map[string]interface{}{},
		})
	}))
	defer server.Close()

	c, err := New(Config{
		BaseURL: server.URL,
		APIKey:  "test-key",
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	resp, err := c.RunAWSOrgSync(context.Background(), AWSOrgSyncRequest{})
	if err != nil {
		t.Fatalf("RunAWSOrgSync returned error: %v", err)
	}
	if resp.Provider != "aws_org" || resp.Validate {
		t.Fatalf("unexpected response: %+v", resp)
	}
}

func TestRunK8sSync_SendsRequestAndParsesResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/api/v1/sync/k8s" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}

		var req map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode request body: %v", err)
		}
		if req["kubeconfig"] != "/tmp/kubeconfig" {
			t.Fatalf("expected kubeconfig /tmp/kubeconfig, got %#v", req["kubeconfig"])
		}
		if req["context"] != "prod-context" {
			t.Fatalf("expected context prod-context, got %#v", req["context"])
		}
		if req["namespace"] != "payments" {
			t.Fatalf("expected namespace payments, got %#v", req["namespace"])
		}
		if req["concurrency"] != float64(6) {
			t.Fatalf("expected concurrency=6, got %#v", req["concurrency"])
		}
		if req["validate"] != true {
			t.Fatalf("expected validate=true, got %#v", req["validate"])
		}
		tables, ok := req["tables"].([]interface{})
		if !ok || len(tables) != 2 || tables[0] != "k8s_pods" || tables[1] != "k8s_services" {
			t.Fatalf("unexpected tables payload: %#v", req["tables"])
		}

		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"provider": "k8s",
			"validate": true,
			"results": []map[string]interface{}{
				{
					"table":    "k8s_pods",
					"synced":   5,
					"errors":   0,
					"duration": float64(2000000000),
				},
			},
		})
	}))
	defer server.Close()

	c, err := New(Config{
		BaseURL: server.URL,
		APIKey:  "test-key",
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	resp, err := c.RunK8sSync(context.Background(), K8sSyncRequest{
		Kubeconfig:  " /tmp/kubeconfig ",
		Context:     " prod-context ",
		Namespace:   " payments ",
		Concurrency: 6,
		Tables:      []string{"k8s_pods", "k8s_services"},
		Validate:    true,
	})
	if err != nil {
		t.Fatalf("RunK8sSync returned error: %v", err)
	}
	if resp.Provider != "k8s" || !resp.Validate || len(resp.Results) != 1 {
		t.Fatalf("unexpected response: %+v", resp)
	}
	if resp.Results[0].Table != "k8s_pods" || resp.Results[0].Synced != 5 {
		t.Fatalf("unexpected first result: %+v", resp.Results[0])
	}
}

func TestRunK8sSync_EmptyRequestBodyForDefaultBehavior(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/sync/k8s" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}

		var req map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
			t.Fatalf("decode request body: %v", err)
		}
		if len(req) != 0 {
			t.Fatalf("expected empty request body, got %#v", req)
		}

		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"provider": "k8s",
			"validate": false,
			"results":  []map[string]interface{}{},
		})
	}))
	defer server.Close()

	c, err := New(Config{
		BaseURL: server.URL,
		APIKey:  "test-key",
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	resp, err := c.RunK8sSync(context.Background(), K8sSyncRequest{})
	if err != nil {
		t.Fatalf("RunK8sSync returned error: %v", err)
	}
	if resp.Provider != "k8s" || resp.Validate {
		t.Fatalf("unexpected response: %+v", resp)
	}
}

func TestRunGCPSync_SendsRequestAndParsesResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/api/v1/sync/gcp" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}

		var req map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode request body: %v", err)
		}
		if req["project"] != "my-project" {
			t.Fatalf("expected project my-project, got %#v", req["project"])
		}
		if req["concurrency"] != float64(7) {
			t.Fatalf("expected concurrency=7, got %#v", req["concurrency"])
		}
		if req["validate"] != true {
			t.Fatalf("expected validate=true, got %#v", req["validate"])
		}
		if req["permission_usage_lookback_days"] != float64(120) {
			t.Fatalf("expected permission_usage_lookback_days=120, got %#v", req["permission_usage_lookback_days"])
		}
		if req["permission_removal_threshold_days"] != float64(240) {
			t.Fatalf("expected permission_removal_threshold_days=240, got %#v", req["permission_removal_threshold_days"])
		}
		targetGroups, ok := req["gcp_iam_target_groups"].([]interface{})
		if !ok || len(targetGroups) != 2 || targetGroups[0] != "eng@example.com" || targetGroups[1] != "ops@example.com" {
			t.Fatalf("unexpected gcp_iam_target_groups payload: %#v", req["gcp_iam_target_groups"])
		}
		tables, ok := req["tables"].([]interface{})
		if !ok || len(tables) != 2 || tables[0] != "gcp_compute_instances" || tables[1] != "gcp_storage_buckets" {
			t.Fatalf("unexpected tables payload: %#v", req["tables"])
		}

		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"provider":                "gcp",
			"validate":                true,
			"relationships_extracted": 9,
			"results": []map[string]interface{}{
				{
					"table":    "gcp_compute_instances",
					"synced":   5,
					"errors":   0,
					"duration": float64(1000000000),
				},
			},
		})
	}))
	defer server.Close()

	c, err := New(Config{
		BaseURL: server.URL,
		APIKey:  "test-key",
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	resp, err := c.RunGCPSync(context.Background(), GCPSyncRequest{
		Project:                        " my-project ",
		Concurrency:                    7,
		Tables:                         []string{"gcp_compute_instances", "gcp_storage_buckets"},
		Validate:                       true,
		PermissionUsageLookbackDays:    120,
		PermissionRemovalThresholdDays: 240,
		GCPIAMTargetGroups:             []string{" eng@example.com ", "ops@example.com"},
	})
	if err != nil {
		t.Fatalf("RunGCPSync returned error: %v", err)
	}
	if resp.Provider != "gcp" || !resp.Validate || len(resp.Results) != 1 {
		t.Fatalf("unexpected response: %+v", resp)
	}
	if resp.Results[0].Table != "gcp_compute_instances" || resp.Results[0].Synced != 5 {
		t.Fatalf("unexpected first result: %+v", resp.Results[0])
	}
	if resp.RelationshipsExtracted != 9 {
		t.Fatalf("unexpected relationship count: %d", resp.RelationshipsExtracted)
	}
}

func TestRunGCPSync_EmptyRequestBodyForDefaultBehavior(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/sync/gcp" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}

		var req map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
			t.Fatalf("decode request body: %v", err)
		}
		if len(req) != 0 {
			t.Fatalf("expected empty request body, got %#v", req)
		}

		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"provider": "gcp",
			"validate": false,
			"results":  []map[string]interface{}{},
		})
	}))
	defer server.Close()

	c, err := New(Config{
		BaseURL: server.URL,
		APIKey:  "test-key",
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	resp, err := c.RunGCPSync(context.Background(), GCPSyncRequest{})
	if err != nil {
		t.Fatalf("RunGCPSync returned error: %v", err)
	}
	if resp.Provider != "gcp" || resp.Validate {
		t.Fatalf("unexpected response: %+v", resp)
	}
}

func TestRunGCPAssetSync_SendsRequestAndParsesResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/api/v1/sync/gcp-asset" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}

		var req map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode request body: %v", err)
		}
		projects, ok := req["projects"].([]interface{})
		if !ok || len(projects) != 2 || projects[0] != "proj-a" || projects[1] != "proj-b" {
			t.Fatalf("unexpected projects payload: %#v", req["projects"])
		}
		if req["concurrency"] != float64(6) {
			t.Fatalf("expected concurrency=6, got %#v", req["concurrency"])
		}
		if req["validate"] != true {
			t.Fatalf("expected validate=true, got %#v", req["validate"])
		}
		tables, ok := req["tables"].([]interface{})
		if !ok || len(tables) != 2 || tables[0] != "gcp_compute_instances" || tables[1] != "gcp_storage_buckets" {
			t.Fatalf("unexpected tables payload: %#v", req["tables"])
		}

		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"provider": "gcp_asset",
			"validate": true,
			"results": []map[string]interface{}{
				{
					"table":    "gcp_compute_instances",
					"synced":   11,
					"errors":   0,
					"duration": float64(1000000000),
				},
			},
		})
	}))
	defer server.Close()

	c, err := New(Config{
		BaseURL: server.URL,
		APIKey:  "test-key",
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	resp, err := c.RunGCPAssetSync(context.Background(), GCPAssetSyncRequest{
		Projects:    []string{" proj-a ", "proj-b"},
		Concurrency: 6,
		Tables:      []string{"gcp_compute_instances", "gcp_storage_buckets"},
		Validate:    true,
	})
	if err != nil {
		t.Fatalf("RunGCPAssetSync returned error: %v", err)
	}
	if resp.Provider != "gcp_asset" || !resp.Validate || len(resp.Results) != 1 {
		t.Fatalf("unexpected response: %+v", resp)
	}
	if resp.Results[0].Table != "gcp_compute_instances" || resp.Results[0].Synced != 11 {
		t.Fatalf("unexpected first result: %+v", resp.Results[0])
	}
}

func TestRunGCPAssetSync_EmptyRequestBodyForDefaultBehavior(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/sync/gcp-asset" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}

		var req map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
			t.Fatalf("decode request body: %v", err)
		}
		if len(req) != 0 {
			t.Fatalf("expected empty request body, got %#v", req)
		}

		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"provider": "gcp_asset",
			"validate": false,
			"results":  []map[string]interface{}{},
		})
	}))
	defer server.Close()

	c, err := New(Config{
		BaseURL: server.URL,
		APIKey:  "test-key",
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	resp, err := c.RunGCPAssetSync(context.Background(), GCPAssetSyncRequest{})
	if err != nil {
		t.Fatalf("RunGCPAssetSync returned error: %v", err)
	}
	if resp.Provider != "gcp_asset" || resp.Validate {
		t.Fatalf("unexpected response: %+v", resp)
	}
}

func TestRunGCPAssetSync_SendsOrganizationScope(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/sync/gcp-asset" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}

		var req map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode request body: %v", err)
		}
		if req["organization"] != "1234567890" {
			t.Fatalf("expected organization 1234567890, got %#v", req["organization"])
		}
		projects, ok := req["projects"].([]interface{})
		if !ok || len(projects) != 0 {
			t.Fatalf("expected explicit empty projects array in organization request: %#v", req["projects"])
		}

		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"provider": "gcp_asset",
			"validate": false,
			"results":  []map[string]interface{}{},
		})
	}))
	defer server.Close()

	c, err := New(Config{
		BaseURL: server.URL,
		APIKey:  "test-key",
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	resp, err := c.RunGCPAssetSync(context.Background(), GCPAssetSyncRequest{
		Organization: " 1234567890 ",
	})
	if err != nil {
		t.Fatalf("RunGCPAssetSync returned error: %v", err)
	}
	if resp.Provider != "gcp_asset" {
		t.Fatalf("unexpected response: %+v", resp)
	}
}
