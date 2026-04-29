package graphingest

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/graphstore"
)

type stubRunStore struct {
	runs []graphstore.IngestRun
}

func (s *stubRunStore) Ping(context.Context) error { return nil }

func (s *stubRunStore) PutIngestRun(context.Context, graphstore.IngestRun) error { return nil }

func (s *stubRunStore) GetIngestRun(context.Context, string) (graphstore.IngestRun, bool, error) {
	return graphstore.IngestRun{}, false, nil
}

func (s *stubRunStore) ListIngestRuns(_ context.Context, filter graphstore.IngestRunFilter) ([]graphstore.IngestRun, error) {
	runs := []graphstore.IngestRun{}
	for _, run := range s.runs {
		if filter.RuntimeID != "" && run.RuntimeID != filter.RuntimeID {
			continue
		}
		if filter.Status != "" && run.Status != filter.Status {
			continue
		}
		runs = append(runs, run)
	}
	if filter.Limit != 0 && len(runs) > filter.Limit {
		runs = runs[:filter.Limit]
	}
	return runs, nil
}

func TestSensitiveConfigKeyTreatsKeySuffixesAsSensitive(t *testing.T) {
	for _, key := range []string{"key", "api_key", "private_key"} {
		if !sensitiveConfigKey(key) {
			t.Fatalf("sensitiveConfigKey(%q) = false, want true", key)
		}
	}
}

func TestConfigHashIgnoresSensitiveKeyValues(t *testing.T) {
	left := configHash(map[string]string{
		"api_key": "first",
		"domain":  "writer.okta.com",
	})
	right := configHash(map[string]string{
		"api_key": "second",
		"domain":  "writer.okta.com",
	})
	if left != right {
		t.Fatalf("configHash() differed when only api_key changed")
	}
}

func TestRuntimeCheckpointIDDistinguishesOriginalRuntimeIDs(t *testing.T) {
	first := runtimeCheckpointID(RuntimeRequest{}, &cerebrov1.SourceRuntime{Id: "writer_okta_users"}, map[string]string{"domain": "writer.okta.com"})
	second := runtimeCheckpointID(RuntimeRequest{}, &cerebrov1.SourceRuntime{Id: "writer-okta-users"}, map[string]string{"domain": "writer.okta.com"})
	if first == second {
		t.Fatalf("runtimeCheckpointID() collided for distinct runtime ids: %q", first)
	}
	if !strings.HasPrefix(first, "runtime:") || !strings.HasPrefix(second, "runtime:") {
		t.Fatalf("runtimeCheckpointID() = %q, %q; want runtime prefix", first, second)
	}
}

func TestHealthFailedCountDoesNotDependOnPagingLimit(t *testing.T) {
	store := &stubRunStore{
		runs: []graphstore.IngestRun{
			{ID: "failed-1", Status: graphstore.IngestRunStatusFailed},
			{ID: "failed-2", Status: graphstore.IngestRunStatusFailed},
			{ID: "running-1", Status: graphstore.IngestRunStatusRunning},
		},
	}
	result, err := New(nil, nil, nil, store).Health(context.Background(), 1)
	if err != nil {
		t.Fatalf("Health() error = %v", err)
	}
	if result.FailedCount != 2 {
		t.Fatalf("Health().FailedCount = %d, want 2", result.FailedCount)
	}
	if len(result.FailedRuns) != 1 {
		t.Fatalf("len(Health().FailedRuns) = %d, want 1", len(result.FailedRuns))
	}
	if result.RunningCount != 1 {
		t.Fatalf("Health().RunningCount = %d, want 1", result.RunningCount)
	}
	if result.Status != "degraded" {
		t.Fatalf("Health().Status = %q, want degraded", result.Status)
	}
}

func TestGetRunRejectsEmptyID(t *testing.T) {
	_, err := New(nil, nil, nil, &stubRunStore{}).GetRun(context.Background(), " ")
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("GetRun() error = %v, want ErrInvalidRequest", err)
	}
}

func TestListResultJSONUsesStableKeys(t *testing.T) {
	payload, err := json.Marshal(ListResult{
		Runs:        []graphstore.IngestRun{{ID: "run-1"}},
		FailedCount: 1,
	})
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	if strings.Contains(string(payload), "Runs") || strings.Contains(string(payload), "FailedCount") {
		t.Fatalf("ListResult JSON used Go field names: %s", payload)
	}
	if !strings.Contains(string(payload), `"runs"`) || !strings.Contains(string(payload), `"failed_count"`) {
		t.Fatalf("ListResult JSON missing stable keys: %s", payload)
	}
}
