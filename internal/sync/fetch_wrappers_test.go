package sync

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/aws/aws-sdk-go-v2/aws"
)

func TestAWSFetchWithRetryDelegatesToTableFetch(t *testing.T) {
	engine := &SyncEngine{
		logger:       slog.New(slog.NewTextHandler(io.Discard, nil)),
		retryOptions: retryOptions{Attempts: 1},
	}
	cfg := aws.Config{Region: "us-east-1"}

	rows, err := engine.fetchWithRetry(context.Background(), TableSpec{
		Name: "AWS_SAMPLE_TABLE",
		Fetch: func(_ context.Context, gotCfg aws.Config, region string) ([]map[string]interface{}, error) {
			if gotCfg.Region != cfg.Region {
				t.Fatalf("expected config region %q, got %q", cfg.Region, gotCfg.Region)
			}
			if region != "us-west-2" {
				t.Fatalf("expected explicit region us-west-2, got %q", region)
			}
			return []map[string]interface{}{{"_cq_id": "row-1"}}, nil
		},
	}, cfg, "us-west-2")
	if err != nil {
		t.Fatalf("fetchWithRetry returned error: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected one row, got %d", len(rows))
	}
}

func TestGCPFetchWithRetryDelegatesToTableFetch(t *testing.T) {
	engine := &GCPSyncEngine{
		logger:       slog.New(slog.NewTextHandler(io.Discard, nil)),
		projectID:    "project-123",
		retryOptions: retryOptions{Attempts: 1},
	}

	rows, err := engine.fetchWithRetry(context.Background(), GCPTableSpec{
		Name: "GCP_SAMPLE_TABLE",
		Fetch: func(_ context.Context, projectID string) ([]map[string]interface{}, error) {
			if projectID != "project-123" {
				t.Fatalf("expected project-123, got %q", projectID)
			}
			return []map[string]interface{}{{"_cq_id": "row-1"}}, nil
		},
	})
	if err != nil {
		t.Fatalf("fetchWithRetry returned error: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected one row, got %d", len(rows))
	}
}

func TestAzureFetchWithRetryDelegatesToTableFetch(t *testing.T) {
	engine := &AzureSyncEngine{
		logger:         slog.New(slog.NewTextHandler(io.Discard, nil)),
		subscriptionID: "sub-123",
		retryOptions:   retryOptions{Attempts: 1},
	}

	rows, err := engine.fetchWithRetry(context.Background(), AzureTableSpec{
		Name: "AZURE_SAMPLE_TABLE",
		Fetch: func(_ context.Context, cred *azidentity.DefaultAzureCredential, subscriptionID string) ([]map[string]interface{}, error) {
			if cred != nil {
				t.Fatalf("expected nil test credential")
			}
			if subscriptionID != "sub-123" {
				t.Fatalf("expected sub-123, got %q", subscriptionID)
			}
			return []map[string]interface{}{{"_cq_id": "row-1"}}, nil
		},
	})
	if err != nil {
		t.Fatalf("fetchWithRetry returned error: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected one row, got %d", len(rows))
	}
}
