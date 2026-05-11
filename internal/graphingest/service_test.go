package graphingest

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/graphstore"
	"github.com/writer/cerebro/internal/ports"
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

type recordProjectorFunc func(*cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error)

func (f recordProjectorFunc) ProjectRecords(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return f(event)
}

type recordingProjectionGraphStore struct {
	entities map[string]*ports.ProjectedEntity
	links    map[string]*ports.ProjectedLink
}

func (s *recordingProjectionGraphStore) Ping(context.Context) error { return nil }

func (s *recordingProjectionGraphStore) UpsertProjectedEntity(_ context.Context, entity *ports.ProjectedEntity) error {
	if s.entities == nil {
		s.entities = map[string]*ports.ProjectedEntity{}
	}
	s.entities[entity.URN] = entity
	return nil
}

func (s *recordingProjectionGraphStore) UpsertProjectedLink(_ context.Context, link *ports.ProjectedLink) error {
	if s.links == nil {
		s.links = map[string]*ports.ProjectedLink{}
	}
	s.links[link.FromURN+"|"+link.Relation+"|"+link.ToURN] = link
	return nil
}

func TestSensitiveConfigKeyTreatsSecretMarkersAsSensitive(t *testing.T) {
	for _, key := range []string{"key", "api_key", "apiKey", "access_key_id", "secret_access_key", "private_key", "privateKey", "signing_key"} {
		if !sensitiveConfigKey(key) {
			t.Fatalf("sensitiveConfigKey(%q) = false, want true", key)
		}
	}
}

func TestConfigHashIgnoresSensitiveKeyValues(t *testing.T) {
	left := configHash(map[string]string{
		"apiKey":            "first",
		"secret_access_key": "first",
		"domain":            "writer.okta.com",
	})
	right := configHash(map[string]string{
		"apiKey":            "second",
		"secret_access_key": "second",
		"domain":            "writer.okta.com",
	})
	if left != right {
		t.Fatalf("configHash() differed when only sensitive keys changed")
	}
}

func TestConfigHashIncludesNonSecretSelectorKeys(t *testing.T) {
	for _, key := range []string{"region", "lookup_key", "group_key"} {
		left := configHash(map[string]string{key: "first", "domain": "writer.example.com"})
		right := configHash(map[string]string{key: "second", "domain": "writer.example.com"})
		if left == right {
			t.Fatalf("configHash() ignored non-secret selector key %q", key)
		}
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

func TestIngestEventStampsTenantAndRuntime(t *testing.T) {
	event := ingestEvent(&cerebrov1.EventEnvelope{
		Id:       "event-1",
		TenantId: "old-tenant",
		Attributes: map[string]string{
			"existing": "value",
		},
	}, "writer", "writer-github")
	if got := event.GetTenantId(); got != "writer" {
		t.Fatalf("TenantId = %q, want writer", got)
	}
	if got := event.GetAttributes()[ports.EventAttributeSourceRuntimeID]; got != "writer-github" {
		t.Fatalf("source_runtime_id = %q, want writer-github", got)
	}
	if got := event.GetAttributes()["existing"]; got != "value" {
		t.Fatalf("existing attribute = %q, want value", got)
	}
}

func TestProjectResponseCoalescedUpsertsUniqueRecords(t *testing.T) {
	store := &recordingProjectionGraphStore{}
	service := &Service{graphStore: store}
	projector := recordProjectorFunc(func(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
		if event.GetTenantId() != "writer" {
			t.Fatalf("event tenant = %q, want writer", event.GetTenantId())
		}
		if got := event.GetAttributes()[ports.EventAttributeSourceRuntimeID]; got != "writer-github-audit" {
			t.Fatalf("source_runtime_id = %q, want writer-github-audit", got)
		}
		return []*ports.ProjectedEntity{{
				URN:        "urn:cerebro:writer:github_org:WriterInternal",
				TenantID:   event.GetTenantId(),
				SourceID:   event.GetSourceId(),
				RuntimeID:  event.GetAttributes()[ports.EventAttributeSourceRuntimeID],
				EntityType: "github.org",
				Label:      "WriterInternal",
				Attributes: map[string]string{"event_id": event.GetId()},
			}},
			[]*ports.ProjectedLink{{
				TenantID:  event.GetTenantId(),
				SourceID:  event.GetSourceId(),
				RuntimeID: event.GetAttributes()[ports.EventAttributeSourceRuntimeID],
				FromURN:   "urn:cerebro:writer:github_repo:WriterInternal/k8s",
				Relation:  "belongs_to",
				ToURN:     "urn:cerebro:writer:github_org:WriterInternal",
				Attributes: map[string]string{
					"event_id": event.GetId(),
				},
			}}, nil
	})
	result, err := service.projectResponseCoalesced(context.Background(), sourceRequest{
		SourceID:  "github",
		RuntimeID: "writer-github-audit",
		TenantID:  "writer",
	}, &cerebrov1.ReadSourceResponse{Events: []*cerebrov1.EventEnvelope{
		{Id: "event-1", SourceId: "github"},
		{Id: "event-2", SourceId: "github"},
	}}, projector)
	if err != nil {
		t.Fatalf("projectResponseCoalesced() error = %v", err)
	}
	if result.EventsRead != 2 {
		t.Fatalf("EventsRead = %d, want 2", result.EventsRead)
	}
	if result.EntitiesProjected != 1 {
		t.Fatalf("EntitiesProjected = %d, want 1 coalesced org upsert", result.EntitiesProjected)
	}
	if result.LinksProjected != 1 {
		t.Fatalf("LinksProjected = %d, want 1 coalesced repo->org link upsert", result.LinksProjected)
	}
	entity := store.entities["urn:cerebro:writer:github_org:WriterInternal"]
	if entity == nil {
		t.Fatal("coalesced org entity missing")
	}
	if got := entity.Attributes["event_id"]; got != "event-2" {
		t.Fatalf("coalesced entity event_id = %q, want latest event-2", got)
	}
	link := store.links["urn:cerebro:writer:github_repo:WriterInternal/k8s|belongs_to|urn:cerebro:writer:github_org:WriterInternal"]
	if link == nil {
		t.Fatal("coalesced repo->org link missing")
	}
	if got := link.Attributes["event_id"]; got != "event-2" {
		t.Fatalf("coalesced link event_id = %q, want latest event-2", got)
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
