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
		Region:      " us-west-2 ",
		MultiRegion: true,
		Concurrency: 11,
		Tables:      []string{"aws_iam_users", "aws_s3_buckets"},
		Validate:    true,
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
