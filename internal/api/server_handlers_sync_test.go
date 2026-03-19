package api

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/app"
	"github.com/writer/cerebro/internal/graph"
	"github.com/writer/cerebro/internal/graph/builders"
	"github.com/writer/cerebro/internal/snowflake"
	nativesync "github.com/writer/cerebro/internal/sync"
)

type syncGraphSource struct {
	mu     sync.Mutex
	latest time.Time
	events []map[string]any
	err    error
	block  bool
}

func (s *syncGraphSource) Query(ctx context.Context, query string, args ...any) (*builders.DataQueryResult, error) {
	_ = ctx
	_ = args
	lower := strings.ToLower(query)

	s.mu.Lock()
	block := s.block
	s.mu.Unlock()

	if block {
		<-ctx.Done()
		return nil, ctx.Err()
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if strings.Contains(lower, "select max(event_time)") && strings.Contains(lower, "from cdc_events") {
		return &builders.DataQueryResult{Rows: []map[string]any{{"latest": s.latest}}, Count: 1}, nil
	}
	if strings.Contains(lower, "select event_id") && strings.Contains(lower, "from cdc_events") {
		if s.err != nil {
			return nil, s.err
		}
		rows := make([]map[string]any, 0, len(s.events))
		rows = append(rows, s.events...)
		return &builders.DataQueryResult{Rows: rows, Count: len(rows)}, nil
	}
	return &builders.DataQueryResult{Rows: []map[string]any{}}, nil
}

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
		if len(req.Subscriptions) != 1 || req.Subscriptions[0] != "sub-123" {
			t.Fatalf("expected normalized subscriptions, got %#v", req.Subscriptions)
		}
		if req.Concurrency != 7 {
			t.Fatalf("expected concurrency 7, got %d", req.Concurrency)
		}
		if req.SubscriptionConcurrency != 3 {
			t.Fatalf("expected subscription concurrency 3, got %d", req.SubscriptionConcurrency)
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
		"subscription":             "  sub-123  ",
		"subscriptions":            []string{"sub-123", "SUB-123"},
		"concurrency":              7,
		"subscription_concurrency": 3,
		"tables":                   []string{"Azure_VM_Instances", "azure_vm_instances", " azure_storage_accounts "},
		"validate":                 true,
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

func TestSyncAzure_RejectsMixedManagementGroupAndSubscriptions(t *testing.T) {
	s := newTestServer(t)
	s.app.Snowflake = &snowflake.Client{}

	w := do(t, s, http.MethodPost, "/api/v1/sync/azure", map[string]interface{}{
		"management_group": "mg-platform",
		"subscriptions":    []string{"sub-123"},
	})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestSyncAzure_NormalizesSubscriptionsCaseInsensitively(t *testing.T) {
	s := newTestServer(t)
	s.app.Snowflake = &snowflake.Client{}

	originalRun := runAzureSyncWithOptions
	t.Cleanup(func() { runAzureSyncWithOptions = originalRun })

	runAzureSyncWithOptions = func(ctx context.Context, client *snowflake.Client, req azureSyncRequest) ([]nativesync.SyncResult, error) {
		if client != s.app.Snowflake {
			t.Fatalf("expected server snowflake client to be passed through")
		}
		want := []string{"SUB-A", "Sub-B"}
		if len(req.Subscriptions) != len(want) {
			t.Fatalf("expected %d normalized subscriptions, got %#v", len(want), req.Subscriptions)
		}
		for i := range want {
			if req.Subscriptions[i] != want[i] {
				t.Fatalf("expected subscriptions %v, got %v", want, req.Subscriptions)
			}
		}
		return []nativesync.SyncResult{{Table: "azure_vm_instances", Synced: 1}}, nil
	}

	w := do(t, s, http.MethodPost, "/api/v1/sync/azure", map[string]interface{}{
		"subscription":  " sub-b ",
		"subscriptions": []string{"SUB-A", "sub-a", "Sub-B"},
	})
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
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

func TestSyncAWS_AppliesIncrementalGraphChangesAfterSync(t *testing.T) {
	s := newTestServer(t)
	s.app.Snowflake = &snowflake.Client{}

	source := &syncGraphSource{}
	builder := builders.NewBuilder(source, s.app.Logger)
	s.app.SecurityGraphBuilder = builder
	s.app.SecurityGraph = builder.Graph()

	base := time.Now().UTC()
	source.latest = base.Add(30 * time.Second)
	source.events = []map[string]any{{
		"event_id":    "evt-1",
		"table_name":  "aws_s3_buckets",
		"resource_id": "arn:aws:s3:::sync-bucket",
		"change_type": "added",
		"provider":    "aws",
		"region":      "us-east-1",
		"account_id":  "111111111111",
		"payload": map[string]any{
			"arn":                 "arn:aws:s3:::sync-bucket",
			"name":                "sync-bucket",
			"account_id":          "111111111111",
			"region":              "us-east-1",
			"block_public_acls":   false,
			"block_public_policy": false,
		},
		"event_time": base.Add(30 * time.Second),
	}}

	originalRun := runAWSSyncWithOptions
	t.Cleanup(func() { runAWSSyncWithOptions = originalRun })
	runAWSSyncWithOptions = func(ctx context.Context, client *snowflake.Client, req awsSyncRequest) (*awsSyncOutcome, error) {
		return &awsSyncOutcome{
			Results: []nativesync.SyncResult{{Table: "aws_s3_buckets", Synced: 1}},
		}, nil
	}

	w := do(t, s, http.MethodPost, "/api/v1/sync/aws", map[string]interface{}{
		"region": "us-east-1",
	})
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	body := decodeJSON(t, w)
	graphUpdate, ok := body["graph_update"].(map[string]any)
	if !ok {
		t.Fatalf("expected graph_update payload, got %#v", body["graph_update"])
	}
	if graphUpdate["status"] != "applied" {
		t.Fatalf("expected graph update status applied, got %#v", graphUpdate)
	}
	if _, ok := s.app.SecurityGraph.GetNode("arn:aws:s3:::sync-bucket"); !ok {
		t.Fatal("expected incrementally applied bucket node in live security graph")
	}
}

func TestSyncAWS_GraphUpdateFailureIsSanitized(t *testing.T) {
	s := newTestServer(t)
	s.app.Snowflake = &snowflake.Client{}

	source := &syncGraphSource{block: true}
	builder := builders.NewBuilder(source, s.app.Logger)
	s.app.SecurityGraphBuilder = builder
	s.app.SecurityGraph = builder.Graph()

	originalRun := runAWSSyncWithOptions
	t.Cleanup(func() { runAWSSyncWithOptions = originalRun })
	runAWSSyncWithOptions = func(ctx context.Context, client *snowflake.Client, req awsSyncRequest) (*awsSyncOutcome, error) {
		return &awsSyncOutcome{
			Results: []nativesync.SyncResult{{Table: "aws_s3_buckets", Synced: 1}},
		}, nil
	}

	originalTimeout := postSyncGraphUpdateTimeout
	postSyncGraphUpdateTimeout = 5 * time.Millisecond
	t.Cleanup(func() { postSyncGraphUpdateTimeout = originalTimeout })

	w := do(t, s, http.MethodPost, "/api/v1/sync/aws", map[string]interface{}{
		"region": "us-east-1",
	})
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	body := decodeJSON(t, w)
	graphUpdate, ok := body["graph_update"].(map[string]any)
	if !ok {
		t.Fatalf("expected graph_update payload, got %#v", body["graph_update"])
	}
	if graphUpdate["status"] != "failed" {
		t.Fatalf("expected graph update status failed, got %#v", graphUpdate)
	}
	if graphUpdate["error"] != "graph update failed" {
		t.Fatalf("expected sanitized graph update error, got %#v", graphUpdate["error"])
	}
	if graphUpdate["error_code"] != "GRAPH_UPDATE_FAILED" {
		t.Fatalf("expected graph update error code, got %#v", graphUpdate["error_code"])
	}
	if strings.Contains(w.Body.String(), context.DeadlineExceeded.Error()) {
		t.Fatalf("expected raw backend error to stay out of response body, got %s", w.Body.String())
	}
}

func TestSyncAWS_GraphUpdateBusyReturnsBusyStatus(t *testing.T) {
	s := newTestServer(t)
	s.app.Snowflake = &snowflake.Client{}

	source := &syncGraphSource{block: true}
	builder := builders.NewBuilder(source, s.app.Logger)
	s.app.SecurityGraphBuilder = builder
	s.app.SecurityGraph = builder.Graph()

	rebuildCtx, rebuildCancel := context.WithCancel(context.Background())
	defer rebuildCancel()
	rebuildDone := make(chan error, 1)
	go func() {
		rebuildDone <- s.app.RebuildSecurityGraph(rebuildCtx)
	}()

	deadline := time.Now().Add(2 * time.Second)
	for {
		snapshot := s.app.GraphBuildSnapshot()
		if snapshot.State == "building" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for rebuild to start, latest snapshot=%+v", snapshot)
		}
		time.Sleep(10 * time.Millisecond)
	}

	originalRun := runAWSSyncWithOptions
	t.Cleanup(func() { runAWSSyncWithOptions = originalRun })
	runAWSSyncWithOptions = func(ctx context.Context, client *snowflake.Client, req awsSyncRequest) (*awsSyncOutcome, error) {
		return &awsSyncOutcome{
			Results: []nativesync.SyncResult{{Table: "aws_s3_buckets", Synced: 1}},
		}, nil
	}

	w := do(t, s, http.MethodPost, "/api/v1/sync/aws", map[string]interface{}{
		"region": "us-east-1",
	})
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	body := decodeJSON(t, w)
	graphUpdate, ok := body["graph_update"].(map[string]any)
	if !ok {
		t.Fatalf("expected graph_update payload, got %#v", body["graph_update"])
	}
	if graphUpdate["status"] != "busy" {
		t.Fatalf("expected graph update status busy, got %#v", graphUpdate)
	}
	if graphUpdate["error_code"] != "GRAPH_UPDATE_BUSY" {
		t.Fatalf("expected graph update busy code, got %#v", graphUpdate["error_code"])
	}

	rebuildCancel()
	select {
	case err := <-rebuildDone:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("expected rebuild to exit on cancel, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for blocked rebuild to exit")
	}
}

func TestSyncAWS_GraphUpdateNoopSummaryUsesEmptyTablesArray(t *testing.T) {
	s := newTestServer(t)
	s.app.Snowflake = &snowflake.Client{}

	source := &syncGraphSource{}
	builder := builders.NewBuilder(source, s.app.Logger)
	s.app.SecurityGraphBuilder = builder
	s.app.SecurityGraph = builder.Graph()

	originalRun := runAWSSyncWithOptions
	t.Cleanup(func() { runAWSSyncWithOptions = originalRun })
	runAWSSyncWithOptions = func(ctx context.Context, client *snowflake.Client, req awsSyncRequest) (*awsSyncOutcome, error) {
		return &awsSyncOutcome{
			Results: []nativesync.SyncResult{{Table: "aws_s3_buckets", Synced: 1}},
		}, nil
	}

	w := do(t, s, http.MethodPost, "/api/v1/sync/aws", map[string]interface{}{
		"region": "us-east-1",
	})
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	body := decodeJSON(t, w)
	graphUpdate, ok := body["graph_update"].(map[string]any)
	if !ok {
		t.Fatalf("expected graph_update payload, got %#v", body["graph_update"])
	}
	if graphUpdate["status"] != "noop" {
		t.Fatalf("expected graph update status noop, got %#v", graphUpdate)
	}
	summary, ok := graphUpdate["summary"].(map[string]any)
	if !ok {
		t.Fatalf("expected graph update summary, got %#v", graphUpdate["summary"])
	}
	tables, ok := summary["tables"].([]any)
	if !ok {
		t.Fatalf("expected tables array, got %#v", summary["tables"])
	}
	if len(tables) != 0 {
		t.Fatalf("expected empty tables array, got %#v", tables)
	}
}

func TestSyncAWS_FullRebuildFallbackReportsAppliedStatus(t *testing.T) {
	s := newTestServer(t)
	s.app.Snowflake = &snowflake.Client{}

	source := &syncGraphSource{err: errors.New("cdc unavailable")}
	builder := builders.NewBuilder(source, s.app.Logger)
	s.app.SecurityGraphBuilder = builder
	s.app.SecurityGraph = builder.Graph()

	originalRun := runAWSSyncWithOptions
	t.Cleanup(func() { runAWSSyncWithOptions = originalRun })
	runAWSSyncWithOptions = func(ctx context.Context, client *snowflake.Client, req awsSyncRequest) (*awsSyncOutcome, error) {
		return &awsSyncOutcome{
			Results: []nativesync.SyncResult{{Table: "aws_s3_buckets", Synced: 1}},
		}, nil
	}

	w := do(t, s, http.MethodPost, "/api/v1/sync/aws", map[string]interface{}{
		"region": "us-east-1",
	})
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	body := decodeJSON(t, w)
	graphUpdate, ok := body["graph_update"].(map[string]any)
	if !ok {
		t.Fatalf("expected graph_update payload, got %#v", body["graph_update"])
	}
	if graphUpdate["status"] != "applied" {
		t.Fatalf("expected graph update status applied after full rebuild fallback, got %#v", graphUpdate)
	}
	summary, ok := graphUpdate["summary"].(map[string]any)
	if !ok {
		t.Fatalf("expected graph update summary, got %#v", graphUpdate["summary"])
	}
	if summary["mode"] != graph.GraphMutationModeFullRebuild {
		t.Fatalf("expected full rebuild summary mode, got %#v", summary["mode"])
	}
}

func TestSyncAWS_AppliesGraphUpdateUsingRuntimeWithoutLocalBuilder(t *testing.T) {
	application := newTestApp(t)
	application.Snowflake = &snowflake.Client{}

	deps := newServerDependenciesFromApp(application)
	deps.SecurityGraph = nil
	deps.SecurityGraphBuilder = nil
	deps.graphRuntime = stubGraphRuntime{
		tryApply: func(_ context.Context, trigger string) (graph.GraphMutationSummary, bool, error) {
			if trigger != "sync_aws" {
				t.Fatalf("expected sync_aws trigger, got %q", trigger)
			}
			return graph.GraphMutationSummary{
				Mode:            graph.GraphMutationModeIncremental,
				Tables:          []string{"aws_s3_buckets"},
				EventsProcessed: 1,
				NodesAdded:      1,
			}, true, nil
		},
	}

	s := NewServerWithDependencies(deps)
	t.Cleanup(func() { s.Close() })

	originalRun := runAWSSyncWithOptions
	t.Cleanup(func() { runAWSSyncWithOptions = originalRun })
	runAWSSyncWithOptions = func(ctx context.Context, client *snowflake.Client, req awsSyncRequest) (*awsSyncOutcome, error) {
		return &awsSyncOutcome{
			Results: []nativesync.SyncResult{{Table: "aws_s3_buckets", Synced: 1}},
		}, nil
	}

	w := do(t, s, http.MethodPost, "/api/v1/sync/aws", map[string]interface{}{
		"region": "us-east-1",
	})
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	body := decodeJSON(t, w)
	graphUpdate, ok := body["graph_update"].(map[string]any)
	if !ok {
		t.Fatalf("expected graph_update payload, got %#v", body["graph_update"])
	}
	if graphUpdate["status"] != "applied" {
		t.Fatalf("expected graph update status applied, got %#v", graphUpdate)
	}
	summary, ok := graphUpdate["summary"].(map[string]any)
	if !ok {
		t.Fatalf("expected graph update summary, got %#v", graphUpdate["summary"])
	}
	if summary["trigger"] != "sync_aws" {
		t.Fatalf("expected summary trigger sync_aws, got %#v", summary["trigger"])
	}
}

func TestSyncAWS_SkipsGraphUpdateWithoutRuntimeOrLocalBuilder(t *testing.T) {
	application := newTestApp(t)
	application.Snowflake = &snowflake.Client{}

	deps := newServerDependenciesFromApp(application)
	deps.SecurityGraph = nil
	deps.SecurityGraphBuilder = nil
	deps.graphRuntime = nil

	s := NewServerWithDependencies(deps)
	t.Cleanup(func() { s.Close() })

	originalRun := runAWSSyncWithOptions
	t.Cleanup(func() { runAWSSyncWithOptions = originalRun })
	runAWSSyncWithOptions = func(ctx context.Context, client *snowflake.Client, req awsSyncRequest) (*awsSyncOutcome, error) {
		return &awsSyncOutcome{
			Results: []nativesync.SyncResult{{Table: "aws_s3_buckets", Synced: 1}},
		}, nil
	}

	w := do(t, s, http.MethodPost, "/api/v1/sync/aws", map[string]interface{}{
		"region": "us-east-1",
	})
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	body := decodeJSON(t, w)
	if _, ok := body["graph_update"]; ok {
		t.Fatalf("expected graph_update to be omitted, got %#v", body["graph_update"])
	}
}

func TestSyncAWS_SkipsGraphUpdateWhenRuntimeAdapterHasNoApplyCapability(t *testing.T) {
	application := &app.App{
		Config:    &app.Config{},
		Snowflake: &snowflake.Client{},
	}

	deps := newServerDependenciesFromApp(application)

	s := NewServerWithDependencies(deps)
	t.Cleanup(func() { s.Close() })

	originalRun := runAWSSyncWithOptions
	t.Cleanup(func() { runAWSSyncWithOptions = originalRun })
	runAWSSyncWithOptions = func(ctx context.Context, client *snowflake.Client, req awsSyncRequest) (*awsSyncOutcome, error) {
		return &awsSyncOutcome{
			Results: []nativesync.SyncResult{{Table: "aws_s3_buckets", Synced: 1}},
		}, nil
	}

	w := do(t, s, http.MethodPost, "/api/v1/sync/aws", map[string]interface{}{
		"region": "us-east-1",
	})
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	body := decodeJSON(t, w)
	if _, ok := body["graph_update"]; ok {
		t.Fatalf("expected graph_update to be omitted, got %#v", body["graph_update"])
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

func TestSyncGCPAsset_RejectsMixedOrganizationAndProjects(t *testing.T) {
	s := newTestServer(t)
	s.app.Snowflake = &snowflake.Client{}

	w := do(t, s, http.MethodPost, "/api/v1/sync/gcp-asset", map[string]interface{}{
		"organization": "1234567890",
		"projects":     []string{"proj-123"},
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

func TestSyncGCPAsset_UsesOrganizationScope(t *testing.T) {
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
		if req.Organization != "1234567890" {
			t.Fatalf("expected organization 1234567890, got %q", req.Organization)
		}
		if len(req.Projects) != 0 {
			t.Fatalf("did not expect explicit projects, got %#v", req.Projects)
		}
		return []nativesync.SyncResult{{Table: "gcp_compute_instances", Synced: 6}}, nil
	}

	w := do(t, s, http.MethodPost, "/api/v1/sync/gcp-asset", map[string]interface{}{
		"organization": " 1234567890 ",
	})
	if !called {
		t.Fatal("expected sync runner to be called")
	}
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}
