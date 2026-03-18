package api

import (
	"context"
	"log/slog"
	"net/http"
	"testing"

	"github.com/evalops/cerebro/internal/app"
	nativesync "github.com/evalops/cerebro/internal/sync"
)

type stubSyncHandlerService struct {
	backfillFunc func(context.Context, int) (syncBackfillResult, error)
	awsFunc      func(context.Context, awsSyncRequest) (awsSyncRunResult, error)
	gcpAssetFunc func(context.Context, gcpAssetSyncRequest) (syncRunResult, error)
}

func (s stubSyncHandlerService) BackfillRelationshipIDs(ctx context.Context, batchSize int) (syncBackfillResult, error) {
	if s.backfillFunc != nil {
		return s.backfillFunc(ctx, batchSize)
	}
	return syncBackfillResult{}, nil
}

func (s stubSyncHandlerService) SyncAzure(context.Context, azureSyncRequest) (syncRunResult, error) {
	return syncRunResult{}, nil
}

func (s stubSyncHandlerService) SyncK8s(context.Context, k8sSyncRequest) (syncRunResult, error) {
	return syncRunResult{}, nil
}

func (s stubSyncHandlerService) SyncAWS(ctx context.Context, req awsSyncRequest) (awsSyncRunResult, error) {
	if s.awsFunc != nil {
		return s.awsFunc(ctx, req)
	}
	return awsSyncRunResult{}, nil
}

func (s stubSyncHandlerService) SyncAWSOrg(context.Context, awsOrgSyncRequest) (awsOrgSyncRunResult, error) {
	return awsOrgSyncRunResult{}, nil
}

func (s stubSyncHandlerService) SyncGCP(context.Context, gcpSyncRequest) (gcpSyncRunResult, error) {
	return gcpSyncRunResult{}, nil
}

func (s stubSyncHandlerService) SyncGCPAsset(ctx context.Context, req gcpAssetSyncRequest) (syncRunResult, error) {
	if s.gcpAssetFunc != nil {
		return s.gcpAssetFunc(ctx, req)
	}
	return syncRunResult{}, nil
}

func TestSyncHandlersUseServiceInterface(t *testing.T) {
	var called bool
	s := NewServerWithDependencies(serverDependencies{
		Config: &app.Config{},
		Logger: slog.Default(),
		syncHandlers: stubSyncHandlerService{
			awsFunc: func(_ context.Context, req awsSyncRequest) (awsSyncRunResult, error) {
				called = true
				if req.Profile != "prod" || req.Region != "us-west-2" || !req.MultiRegion || !req.Validate {
					t.Fatalf("unexpected aws request normalization: %#v", req)
				}
				if len(req.Tables) != 2 || req.Tables[0] != "aws_iam_users" || req.Tables[1] != "aws_s3_buckets" {
					t.Fatalf("unexpected aws tables: %#v", req.Tables)
				}
				return awsSyncRunResult{
					Results:                []nativesync.SyncResult{{Table: "aws_iam_users", Synced: 4}},
					RelationshipsExtracted: 9,
					GraphUpdate:            map[string]any{"status": "applied"},
				}, nil
			},
		},
	})
	t.Cleanup(func() { s.Close() })

	w := do(t, s, http.MethodPost, "/api/v1/sync/aws", map[string]any{
		"profile":      " prod ",
		"region":       " us-west-2 ",
		"multi_region": true,
		"validate":     true,
		"tables":       []string{"AWS_IAM_USERS", " aws_s3_buckets ", "aws_iam_users"},
	})
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for service-backed aws sync, got %d: %s", w.Code, w.Body.String())
	}
	if !called {
		t.Fatal("expected aws sync handler to use sync service")
	}

	body := decodeJSON(t, w)
	if body["relationships_extracted"] != float64(9) {
		t.Fatalf("expected stubbed relationships count, got %#v", body["relationships_extracted"])
	}
	graphUpdate := body["graph_update"].(map[string]any)
	if graphUpdate["status"] != "applied" {
		t.Fatalf("expected stubbed graph update, got %#v", graphUpdate)
	}
}

func TestSyncBackfillUsesServiceInterface(t *testing.T) {
	var batchSize int
	s := NewServerWithDependencies(serverDependencies{
		Config: &app.Config{},
		Logger: slog.Default(),
		syncHandlers: stubSyncHandlerService{
			backfillFunc: func(_ context.Context, got int) (syncBackfillResult, error) {
				batchSize = got
				return syncBackfillResult{Scanned: 5, Updated: 3, Deleted: 1, Skipped: 1}, nil
			},
		},
	})
	t.Cleanup(func() { s.Close() })

	w := do(t, s, http.MethodPost, "/api/v1/sync/backfill-relationships", map[string]any{"batch_size": 321})
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for service-backed backfill, got %d: %s", w.Code, w.Body.String())
	}
	if batchSize != 321 {
		t.Fatalf("expected batch size 321 to reach service, got %d", batchSize)
	}
	body := decodeJSON(t, w)
	if body["updated"] != float64(3) {
		t.Fatalf("expected stubbed backfill response, got %#v", body)
	}
}

func TestSyncGCPAssetUsesServiceInterface(t *testing.T) {
	var called bool
	s := NewServerWithDependencies(serverDependencies{
		Config: &app.Config{},
		Logger: slog.Default(),
		syncHandlers: stubSyncHandlerService{
			gcpAssetFunc: func(_ context.Context, req gcpAssetSyncRequest) (syncRunResult, error) {
				called = true
				if req.Organization != "1234567890" {
					t.Fatalf("expected organization to be trimmed, got %#v", req)
				}
				return syncRunResult{Results: []nativesync.SyncResult{{Table: "gcp_compute_instances", Synced: 2}}}, nil
			},
		},
	})
	t.Cleanup(func() { s.Close() })

	w := do(t, s, http.MethodPost, "/api/v1/sync/gcp-asset", map[string]any{"organization": " 1234567890 "})
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for service-backed gcp asset sync, got %d: %s", w.Code, w.Body.String())
	}
	if !called {
		t.Fatal("expected gcp asset handler to use sync service")
	}
}
