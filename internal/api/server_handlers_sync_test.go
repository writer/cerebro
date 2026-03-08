package api

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/evalops/cerebro/internal/snowflake"
	nativesync "github.com/evalops/cerebro/internal/sync"
)

func TestBackfillRelationshipIDs_RequiresSnowflake(t *testing.T) {
	s := newTestServer(t)

	w := do(t, s, http.MethodPost, "/api/v1/sync/backfill-relationships", map[string]interface{}{
		"batch_size": 100,
	})
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d: %s", w.Code, w.Body.String())
	}
}

func TestBackfillRelationshipIDs_InvalidRequest(t *testing.T) {
	s := newTestServer(t)

	w := do(t, s, http.MethodPost, "/api/v1/sync/backfill-relationships", "not-json")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid request, got %d: %s", w.Code, w.Body.String())
	}
}

func TestSyncAzure_RequiresSnowflake(t *testing.T) {
	s := newTestServer(t)

	w := do(t, s, http.MethodPost, "/api/v1/sync/azure", map[string]interface{}{
		"subscription": "sub-123",
		"concurrency":  10,
		"tables":       []string{"azure_vm_instances"},
	})
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d: %s", w.Code, w.Body.String())
	}
}

func TestSyncAzure_InvalidRequest(t *testing.T) {
	s := newTestServer(t)

	w := do(t, s, http.MethodPost, "/api/v1/sync/azure", "not-json")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid request, got %d: %s", w.Code, w.Body.String())
	}
}

func TestSyncAzure_UsesRequestOptions(t *testing.T) {
	s := newTestServer(t)
	s.app.Snowflake = &snowflake.Client{}

	originalRun := runAzureSyncWithOptions
	t.Cleanup(func() { runAzureSyncWithOptions = originalRun })

	called := false
	runAzureSyncWithOptions = func(ctx context.Context, client *snowflake.Client, req azureSyncRequest) ([]nativesync.SyncResult, error) {
		called = true
		if client != s.app.Snowflake {
			t.Fatalf("expected server snowflake client to be passed through")
		}
		if req.Subscription != "sub-123" {
			t.Fatalf("expected trimmed subscription, got %q", req.Subscription)
		}
		if req.Concurrency != 7 {
			t.Fatalf("expected concurrency 7, got %d", req.Concurrency)
		}
		if len(req.Tables) != 2 || req.Tables[0] != "azure_vm_instances" || req.Tables[1] != "azure_storage_accounts" {
			t.Fatalf("unexpected table filter: %#v", req.Tables)
		}
		if !req.Validate {
			t.Fatal("expected validate=true")
		}
		return []nativesync.SyncResult{{Table: "azure_vm_instances", Synced: 3}}, nil
	}

	w := do(t, s, http.MethodPost, "/api/v1/sync/azure", map[string]interface{}{
		"subscription": "  sub-123  ",
		"concurrency":  7,
		"tables":       []string{"Azure_VM_Instances", "azure_vm_instances", " azure_storage_accounts "},
		"validate":     true,
	})
	if !called {
		t.Fatal("expected sync runner to be called")
	}
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `"provider":"azure"`) {
		t.Fatalf("expected provider in response body, got %s", w.Body.String())
	}
}

func TestSyncK8s_RequiresSnowflake(t *testing.T) {
	s := newTestServer(t)

	w := do(t, s, http.MethodPost, "/api/v1/sync/k8s", map[string]interface{}{
		"namespace":   "default",
		"concurrency": 8,
		"tables":      []string{"k8s_pods"},
	})
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d: %s", w.Code, w.Body.String())
	}
}

func TestSyncK8s_InvalidRequest(t *testing.T) {
	s := newTestServer(t)

	w := do(t, s, http.MethodPost, "/api/v1/sync/k8s", "not-json")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid request, got %d: %s", w.Code, w.Body.String())
	}
}

func TestSyncK8s_UsesRequestOptions(t *testing.T) {
	s := newTestServer(t)
	s.app.Snowflake = &snowflake.Client{}

	originalRun := runK8sSyncWithOptions
	t.Cleanup(func() { runK8sSyncWithOptions = originalRun })

	called := false
	runK8sSyncWithOptions = func(ctx context.Context, client *snowflake.Client, req k8sSyncRequest) ([]nativesync.SyncResult, error) {
		called = true
		if client != s.app.Snowflake {
			t.Fatalf("expected server snowflake client to be passed through")
		}
		if req.Kubeconfig != "/tmp/kubeconfig" {
			t.Fatalf("expected kubeconfig /tmp/kubeconfig, got %q", req.Kubeconfig)
		}
		if req.Context != "prod-context" {
			t.Fatalf("expected context prod-context, got %q", req.Context)
		}
		if req.Namespace != "payments" {
			t.Fatalf("expected namespace payments, got %q", req.Namespace)
		}
		if req.Concurrency != 4 {
			t.Fatalf("expected concurrency 4, got %d", req.Concurrency)
		}
		if len(req.Tables) != 2 || req.Tables[0] != "k8s_pods" || req.Tables[1] != "k8s_services" {
			t.Fatalf("unexpected table filter: %#v", req.Tables)
		}
		if !req.Validate {
			t.Fatal("expected validate=true")
		}
		return []nativesync.SyncResult{{Table: "k8s_pods", Synced: 2}}, nil
	}

	w := do(t, s, http.MethodPost, "/api/v1/sync/k8s", map[string]interface{}{
		"kubeconfig":  " /tmp/kubeconfig ",
		"context":     " prod-context ",
		"namespace":   " payments ",
		"concurrency": 4,
		"tables":      []string{"K8S_PODS", "k8s_pods", " k8s_services "},
		"validate":    true,
	})
	if !called {
		t.Fatal("expected sync runner to be called")
	}
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `"provider":"k8s"`) {
		t.Fatalf("expected provider in response body, got %s", w.Body.String())
	}
}

func TestSyncAWS_RequiresSnowflake(t *testing.T) {
	s := newTestServer(t)

	w := do(t, s, http.MethodPost, "/api/v1/sync/aws", map[string]interface{}{
		"region":      "us-west-2",
		"concurrency": 4,
		"tables":      []string{"aws_iam_users"},
	})
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d: %s", w.Code, w.Body.String())
	}
}

func TestSyncAWS_InvalidRequest(t *testing.T) {
	s := newTestServer(t)

	w := do(t, s, http.MethodPost, "/api/v1/sync/aws", "not-json")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid request, got %d: %s", w.Code, w.Body.String())
	}
}

func TestSyncAWS_UsesRequestOptions(t *testing.T) {
	s := newTestServer(t)
	s.app.Snowflake = &snowflake.Client{}

	originalRun := runAWSSyncWithOptions
	t.Cleanup(func() { runAWSSyncWithOptions = originalRun })

	called := false
	runAWSSyncWithOptions = func(ctx context.Context, client *snowflake.Client, req awsSyncRequest) (*awsSyncOutcome, error) {
		called = true
		if client != s.app.Snowflake {
			t.Fatalf("expected server snowflake client to be passed through")
		}
		if req.Profile != "prod-profile" {
			t.Fatalf("expected profile prod-profile, got %q", req.Profile)
		}
		if req.Region != "us-west-2" {
			t.Fatalf("expected region us-west-2, got %q", req.Region)
		}
		if !req.MultiRegion {
			t.Fatal("expected multi_region=true")
		}
		if req.Concurrency != 6 {
			t.Fatalf("expected concurrency 6, got %d", req.Concurrency)
		}
		if len(req.Tables) != 2 || req.Tables[0] != "aws_iam_users" || req.Tables[1] != "aws_s3_buckets" {
			t.Fatalf("unexpected table filter: %#v", req.Tables)
		}
		if !req.Validate {
			t.Fatal("expected validate=true")
		}
		return &awsSyncOutcome{
			Results:                    []nativesync.SyncResult{{Table: "aws_iam_users", Synced: 4}},
			RelationshipsExtracted:     11,
			RelationshipsSkippedReason: "test reason",
		}, nil
	}

	w := do(t, s, http.MethodPost, "/api/v1/sync/aws", map[string]interface{}{
		"profile":      " prod-profile ",
		"region":       " us-west-2 ",
		"multi_region": true,
		"concurrency":  6,
		"tables":       []string{"AWS_IAM_USERS", "aws_iam_users", " aws_s3_buckets "},
		"validate":     true,
	})
	if !called {
		t.Fatal("expected sync runner to be called")
	}
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `"provider":"aws"`) {
		t.Fatalf("expected provider in response body, got %s", w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `"relationships_extracted":11`) {
		t.Fatalf("expected relationships count in response body, got %s", w.Body.String())
	}
}

func TestSyncAWSOrg_RequiresSnowflake(t *testing.T) {
	s := newTestServer(t)

	w := do(t, s, http.MethodPost, "/api/v1/sync/aws-org", map[string]interface{}{
		"org_role": "OrganizationAccountAccessRole",
	})
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d: %s", w.Code, w.Body.String())
	}
}

func TestSyncAWSOrg_InvalidRequest(t *testing.T) {
	s := newTestServer(t)

	w := do(t, s, http.MethodPost, "/api/v1/sync/aws-org", "not-json")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid request, got %d: %s", w.Code, w.Body.String())
	}
}

func TestSyncAWSOrg_UsesRequestOptions(t *testing.T) {
	s := newTestServer(t)
	s.app.Snowflake = &snowflake.Client{}

	originalRun := runAWSOrgSyncWithOptions
	t.Cleanup(func() { runAWSOrgSyncWithOptions = originalRun })

	called := false
	runAWSOrgSyncWithOptions = func(ctx context.Context, client *snowflake.Client, req awsOrgSyncRequest) (*awsOrgSyncOutcome, error) {
		called = true
		if client != s.app.Snowflake {
			t.Fatalf("expected server snowflake client to be passed through")
		}
		if req.Profile != "prod-profile" {
			t.Fatalf("expected profile prod-profile, got %q", req.Profile)
		}
		if req.Region != "us-west-2" {
			t.Fatalf("expected region us-west-2, got %q", req.Region)
		}
		if !req.MultiRegion {
			t.Fatal("expected multi_region=true")
		}
		if req.Concurrency != 6 {
			t.Fatalf("expected concurrency 6, got %d", req.Concurrency)
		}
		if req.OrgRole != "OrganizationAccountAccessRole" {
			t.Fatalf("expected org role OrganizationAccountAccessRole, got %q", req.OrgRole)
		}
		if req.AccountConcurrency != 3 {
			t.Fatalf("expected account concurrency 3, got %d", req.AccountConcurrency)
		}
		if len(req.IncludeAccounts) != 2 || req.IncludeAccounts[0] != "111111111111" || req.IncludeAccounts[1] != "222222222222" {
			t.Fatalf("unexpected include account filter: %#v", req.IncludeAccounts)
		}
		if len(req.ExcludeAccounts) != 1 || req.ExcludeAccounts[0] != "333333333333" {
			t.Fatalf("unexpected exclude account filter: %#v", req.ExcludeAccounts)
		}
		if len(req.Tables) != 2 || req.Tables[0] != "aws_iam_users" || req.Tables[1] != "aws_s3_buckets" {
			t.Fatalf("unexpected table filter: %#v", req.Tables)
		}
		if !req.Validate {
			t.Fatal("expected validate=true")
		}
		return &awsOrgSyncOutcome{
			Results:       []nativesync.SyncResult{{Table: "aws_iam_users", Synced: 4}},
			AccountErrors: []string{"account 999999999999: access denied"},
		}, nil
	}

	w := do(t, s, http.MethodPost, "/api/v1/sync/aws-org", map[string]interface{}{
		"profile":             " prod-profile ",
		"region":              " us-west-2 ",
		"multi_region":        true,
		"concurrency":         6,
		"tables":              []string{"AWS_IAM_USERS", "aws_iam_users", " aws_s3_buckets "},
		"validate":            true,
		"org_role":            " OrganizationAccountAccessRole ",
		"include_accounts":    []string{" 111111111111 ", "111111111111", "222222222222"},
		"exclude_accounts":    []string{"333333333333", "333333333333"},
		"account_concurrency": 3,
	})
	if !called {
		t.Fatal("expected sync runner to be called")
	}
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `"provider":"aws_org"`) {
		t.Fatalf("expected provider in response body, got %s", w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `"account_errors":["account 999999999999: access denied"]`) {
		t.Fatalf("expected account errors in response body, got %s", w.Body.String())
	}
}

func TestSyncGCP_RequiresSnowflake(t *testing.T) {
	s := newTestServer(t)

	w := do(t, s, http.MethodPost, "/api/v1/sync/gcp", map[string]interface{}{
		"project":     "proj-123",
		"concurrency": 4,
		"tables":      []string{"gcp_compute_instances"},
	})
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d: %s", w.Code, w.Body.String())
	}
}

func TestSyncGCP_InvalidRequest(t *testing.T) {
	s := newTestServer(t)

	w := do(t, s, http.MethodPost, "/api/v1/sync/gcp", "not-json")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid request, got %d: %s", w.Code, w.Body.String())
	}
}

func TestSyncGCP_RequiresProject(t *testing.T) {
	s := newTestServer(t)
	s.app.Snowflake = &snowflake.Client{}

	w := do(t, s, http.MethodPost, "/api/v1/sync/gcp", map[string]interface{}{
		"concurrency": 4,
		"tables":      []string{"gcp_compute_instances"},
	})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestSyncGCP_UsesRequestOptions(t *testing.T) {
	s := newTestServer(t)
	s.app.Snowflake = &snowflake.Client{}

	originalRun := runGCPSyncWithOptions
	t.Cleanup(func() { runGCPSyncWithOptions = originalRun })

	called := false
	runGCPSyncWithOptions = func(ctx context.Context, client *snowflake.Client, req gcpSyncRequest) (*gcpSyncOutcome, error) {
		called = true
		if client != s.app.Snowflake {
			t.Fatalf("expected server snowflake client to be passed through")
		}
		if req.Project != "proj-123" {
			t.Fatalf("expected project proj-123, got %q", req.Project)
		}
		if req.Concurrency != 5 {
			t.Fatalf("expected concurrency 5, got %d", req.Concurrency)
		}
		if len(req.Tables) != 2 || req.Tables[0] != "gcp_compute_instances" || req.Tables[1] != "gcp_storage_buckets" {
			t.Fatalf("unexpected table filter: %#v", req.Tables)
		}
		if !req.Validate {
			t.Fatal("expected validate=true")
		}
		return &gcpSyncOutcome{
			Results:                    []nativesync.SyncResult{{Table: "gcp_compute_instances", Synced: 6}},
			RelationshipsExtracted:     8,
			RelationshipsSkippedReason: "test reason",
		}, nil
	}

	w := do(t, s, http.MethodPost, "/api/v1/sync/gcp", map[string]interface{}{
		"project":     "  proj-123  ",
		"concurrency": 5,
		"tables":      []string{"GCP_COMPUTE_INSTANCES", "gcp_compute_instances", " gcp_storage_buckets "},
		"validate":    true,
	})
	if !called {
		t.Fatal("expected sync runner to be called")
	}
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `"provider":"gcp"`) {
		t.Fatalf("expected provider in response body, got %s", w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `"relationships_extracted":8`) {
		t.Fatalf("expected relationships count in response body, got %s", w.Body.String())
	}
}

func TestSyncGCPAsset_RequiresSnowflake(t *testing.T) {
	s := newTestServer(t)

	w := do(t, s, http.MethodPost, "/api/v1/sync/gcp-asset", map[string]interface{}{
		"projects":    []string{"proj-123"},
		"concurrency": 4,
		"tables":      []string{"gcp_compute_instances"},
	})
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d: %s", w.Code, w.Body.String())
	}
}

func TestSyncGCPAsset_InvalidRequest(t *testing.T) {
	s := newTestServer(t)

	w := do(t, s, http.MethodPost, "/api/v1/sync/gcp-asset", "not-json")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid request, got %d: %s", w.Code, w.Body.String())
	}
}

func TestSyncGCPAsset_RequiresProjects(t *testing.T) {
	s := newTestServer(t)
	s.app.Snowflake = &snowflake.Client{}

	w := do(t, s, http.MethodPost, "/api/v1/sync/gcp-asset", map[string]interface{}{
		"concurrency": 4,
		"tables":      []string{"gcp_compute_instances"},
	})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestSyncGCPAsset_UsesRequestOptions(t *testing.T) {
	s := newTestServer(t)
	s.app.Snowflake = &snowflake.Client{}

	originalRun := runGCPAssetSyncWithOptions
	t.Cleanup(func() { runGCPAssetSyncWithOptions = originalRun })

	called := false
	runGCPAssetSyncWithOptions = func(ctx context.Context, client *snowflake.Client, req gcpAssetSyncRequest) ([]nativesync.SyncResult, error) {
		called = true
		if client != s.app.Snowflake {
			t.Fatalf("expected server snowflake client to be passed through")
		}
		if len(req.Projects) != 2 || req.Projects[0] != "proj-123" || req.Projects[1] != "proj-456" {
			t.Fatalf("unexpected projects: %#v", req.Projects)
		}
		if req.Concurrency != 5 {
			t.Fatalf("expected concurrency 5, got %d", req.Concurrency)
		}
		if len(req.Tables) != 2 || req.Tables[0] != "gcp_compute_instances" || req.Tables[1] != "gcp_storage_buckets" {
			t.Fatalf("unexpected table filter: %#v", req.Tables)
		}
		if !req.Validate {
			t.Fatal("expected validate=true")
		}
		return []nativesync.SyncResult{{Table: "gcp_compute_instances", Synced: 6}}, nil
	}

	w := do(t, s, http.MethodPost, "/api/v1/sync/gcp-asset", map[string]interface{}{
		"projects":    []string{"  proj-123  ", "PROJ-123", "proj-456"},
		"concurrency": 5,
		"tables":      []string{"GCP_COMPUTE_INSTANCES", "gcp_compute_instances", " gcp_storage_buckets "},
		"validate":    true,
	})
	if !called {
		t.Fatal("expected sync runner to be called")
	}
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `"provider":"gcp_asset"`) {
		t.Fatalf("expected provider in response body, got %s", w.Body.String())
	}
}
