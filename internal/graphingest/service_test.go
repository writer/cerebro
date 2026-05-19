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
	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/internal/sourceconfig"
)

type stubRunStore struct {
	runs    []graphstore.IngestRun
	putRuns []graphstore.IngestRun
	putFunc func(context.Context, graphstore.IngestRun) error
}

func (s *stubRunStore) Ping(context.Context) error { return nil }

func (s *stubRunStore) PutIngestRun(ctx context.Context, run graphstore.IngestRun) error {
	s.putRuns = append(s.putRuns, run)
	if s.putFunc != nil {
		return s.putFunc(ctx, run)
	}
	return nil
}

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

func (f recordProjectorFunc) Project(_ context.Context, event *cerebrov1.EventEnvelope) (ports.ProjectionResult, error) {
	entities, links, err := f(event)
	return ports.ProjectionResult{
		EntitiesProjected: uint32(len(entities)),
		LinksProjected:    uint32(len(links)),
	}, err
}

func (f recordProjectorFunc) ProjectRecords(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return f(event)
}

type recordingProjectionGraphStore struct {
	entities      map[string]*ports.ProjectedEntity
	links         map[string]*ports.ProjectedLink
	upsertLinkErr error
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
	if s.upsertLinkErr != nil {
		return s.upsertLinkErr
	}
	if s.links == nil {
		s.links = map[string]*ports.ProjectedLink{}
	}
	s.links[link.FromURN+"|"+link.Relation+"|"+link.ToURN] = link
	return nil
}

type singlePageSource struct {
	id     string
	events []*cerebrov1.EventEnvelope
}

func (s *singlePageSource) Spec() *cerebrov1.SourceSpec {
	return &cerebrov1.SourceSpec{Id: s.id, Name: "Single Page"}
}

func (s *singlePageSource) Check(context.Context, sourcecdk.Config) error { return nil }

func (s *singlePageSource) Discover(context.Context, sourcecdk.Config) ([]sourcecdk.URN, error) {
	return nil, nil
}

func (s *singlePageSource) Read(context.Context, sourcecdk.Config, *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
	return sourcecdk.Pull{Events: s.events}, nil
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

func TestConfigHashIgnoresInternalRuntimeMetadata(t *testing.T) {
	base := configHash(map[string]string{"domain": "writer.okta.com"})
	withInternal := configHash(map[string]string{
		"domain":                               "writer.okta.com",
		sourceconfig.RuntimeTenantIDKey:        "writer",
		sourceconfig.AWSAssumeRoleAllowlistKey: "writer=arn:aws:iam::123456789012:role/cerebro-org-scan-role",
	})
	if base != withInternal {
		t.Fatal("configHash() changed when only internal runtime metadata changed")
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

func TestProjectResponseCoalescedPreservesNewestObservationAttributes(t *testing.T) {
	store := &recordingProjectionGraphStore{}
	service := &Service{graphStore: store}
	projector := recordProjectorFunc(func(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
		at := "2026-05-11T10:00:00Z"
		if event.GetId() == "older-event" {
			at = "2026-05-10T10:00:00Z"
		}
		return []*ports.ProjectedEntity{{
				URN:        "urn:cerebro:writer:github_user:alice",
				TenantID:   event.GetTenantId(),
				SourceID:   event.GetSourceId(),
				RuntimeID:  event.GetAttributes()[ports.EventAttributeSourceRuntimeID],
				EntityType: "github.user",
				Label:      "alice",
				Attributes: map[string]string{
					"at":             at,
					"event_id":       event.GetId(),
					"login":          event.GetId(),
					"outcome_result": event.GetId(),
				},
			}},
			[]*ports.ProjectedLink{{
				TenantID:  event.GetTenantId(),
				SourceID:  event.GetSourceId(),
				RuntimeID: event.GetAttributes()[ports.EventAttributeSourceRuntimeID],
				FromURN:   "urn:cerebro:writer:github_user:alice",
				Relation:  "acted_on",
				ToURN:     "urn:cerebro:writer:github_repo:writer/cerebro",
				Attributes: map[string]string{
					"action":         "git.clone",
					"at":             at,
					"event_id":       event.GetId(),
					"event_type":     event.GetId(),
					"outcome_result": event.GetId(),
					"target":         event.GetId(),
				},
			}}, nil
	})
	_, err := service.projectResponseCoalesced(context.Background(), sourceRequest{
		SourceID:  "github",
		RuntimeID: "writer-github-audit",
		TenantID:  "writer",
	}, &cerebrov1.ReadSourceResponse{Events: []*cerebrov1.EventEnvelope{
		{Id: "newer-event", SourceId: "github"},
		{Id: "older-event", SourceId: "github"},
	}}, projector)
	if err != nil {
		t.Fatalf("projectResponseCoalesced() error = %v", err)
	}
	entity := store.entities["urn:cerebro:writer:github_user:alice"]
	if entity == nil {
		t.Fatal("coalesced github.user entity missing")
	}
	if got := entity.Attributes["at"]; got != "2026-05-11T10:00:00Z" {
		t.Fatalf("coalesced entity at = %q, want newest timestamp", got)
	}
	if got := entity.Attributes["event_id"]; got != "newer-event" {
		t.Fatalf("coalesced entity event_id = %q, want newer-event coupled to newest observation", got)
	}
	if got := entity.Attributes["outcome_result"]; got != "newer-event" {
		t.Fatalf("coalesced entity outcome_result = %q, want newer-event coupled to newest observation", got)
	}
	if got := entity.Attributes["login"]; got != "older-event" {
		t.Fatalf("coalesced entity non-observation attribute login = %q, want older-event latest write", got)
	}
	link := store.links["urn:cerebro:writer:github_user:alice|acted_on|urn:cerebro:writer:github_repo:writer/cerebro"]
	if link == nil {
		t.Fatal("coalesced acted_on link missing")
	}
	if got := link.Attributes["at"]; got != "2026-05-11T10:00:00Z" {
		t.Fatalf("coalesced link at = %q, want newest timestamp", got)
	}
	if got := link.Attributes["event_id"]; got != "newer-event" {
		t.Fatalf("coalesced link event_id = %q, want newer-event coupled to newest observation", got)
	}
	if got := link.Attributes["event_type"]; got != "newer-event" {
		t.Fatalf("coalesced link event_type = %q, want newer-event coupled to newest observation", got)
	}
	if got := link.Attributes["outcome_result"]; got != "newer-event" {
		t.Fatalf("coalesced link outcome_result = %q, want newer-event coupled to newest observation", got)
	}
	if got := link.Attributes["target"]; got != "older-event" {
		t.Fatalf("coalesced link non-observation attribute target = %q, want older-event latest write", got)
	}
}

func TestMergeStringMapClearsOlderObservationMetadataMissingFromNewerAt(t *testing.T) {
	merged := mergeStringMap(
		map[string]string{
			"at":             "2026-05-10T10:00:00Z",
			"event_id":       "older-event",
			"outcome_reason": "older reason",
			"transaction_id": "older-txn",
			"target":         "repo",
		},
		map[string]string{
			"at":       "2026-05-11T10:00:00Z",
			"event_id": "newer-event",
		},
	)
	for key, want := range map[string]string{
		"at":       "2026-05-11T10:00:00Z",
		"event_id": "newer-event",
		"target":   "repo",
	} {
		if got := merged[key]; got != want {
			t.Fatalf("merged[%s] = %q, want %q", key, got, want)
		}
	}
	for _, key := range []string{"outcome_reason", "transaction_id"} {
		if got, exists := merged[key]; exists {
			t.Fatalf("merged[%s] = %q, want missing because newer observation omitted it", key, got)
		}
	}
}

func TestIngestSourceReturnsPartialCountersOnProjectionFailure(t *testing.T) {
	upsertErr := errors.New("neo4j timeout")
	registry, err := sourcecdk.NewRegistry(&singlePageSource{
		id: "partial",
		events: []*cerebrov1.EventEnvelope{{
			Id:       "event-1",
			SourceId: "partial",
		}},
	})
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	store := &recordingProjectionGraphStore{upsertLinkErr: upsertErr}
	projector := recordProjectorFunc(func(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
		return []*ports.ProjectedEntity{{
				URN:        "urn:cerebro:tenant:partial_entity:one",
				TenantID:   event.GetTenantId(),
				SourceID:   event.GetSourceId(),
				RuntimeID:  event.GetAttributes()[ports.EventAttributeSourceRuntimeID],
				EntityType: "partial.entity",
				Label:      "one",
			}},
			[]*ports.ProjectedLink{{
				TenantID:  event.GetTenantId(),
				SourceID:  event.GetSourceId(),
				RuntimeID: event.GetAttributes()[ports.EventAttributeSourceRuntimeID],
				FromURN:   "urn:cerebro:tenant:partial_entity:one",
				Relation:  "related_to",
				ToURN:     "urn:cerebro:tenant:partial_entity:one",
			}}, nil
	})
	service := New(registry, nil, projector, store)

	result, err := service.ingestSource(context.Background(), sourceRequest{
		SourceID:  "partial",
		RuntimeID: "tenant-partial",
		TenantID:  "tenant",
		PageLimit: 1,
	})
	if !errors.Is(err, upsertErr) {
		t.Fatalf("ingestSource() error = %v, want %v", err, upsertErr)
	}
	if result == nil {
		t.Fatal("ingestSource() result = nil, want partial counters")
	}
	if result.PagesRead != 1 || result.EventsRead != 1 || result.EntitiesProjected != 1 || result.LinksProjected != 0 {
		t.Fatalf("partial counters = pages %d events %d entities %d links %d, want 1/1/1/0", result.PagesRead, result.EventsRead, result.EntitiesProjected, result.LinksProjected)
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

func TestHealthUsesLatestRunPerRuntime(t *testing.T) {
	store := &stubRunStore{
		runs: []graphstore.IngestRun{
			{
				ID:        "old-failed",
				RuntimeID: "runtime-a",
				Status:    graphstore.IngestRunStatusFailed,
				StartedAt: "2026-05-12T10:00:00Z",
			},
			{
				ID:        "new-completed",
				RuntimeID: "runtime-a",
				Status:    graphstore.IngestRunStatusCompleted,
				StartedAt: "2026-05-12T11:00:00Z",
			},
			{
				ID:        "latest-running",
				RuntimeID: "runtime-b",
				Status:    graphstore.IngestRunStatusRunning,
				StartedAt: "2026-05-12T12:00:00Z",
			},
		},
	}
	result, err := New(nil, nil, nil, store).Health(context.Background(), 10)
	if err != nil {
		t.Fatalf("Health() error = %v", err)
	}
	if result.FailedCount != 0 {
		t.Fatalf("Health().FailedCount = %d, want 0", result.FailedCount)
	}
	if result.RunningCount != 1 {
		t.Fatalf("Health().RunningCount = %d, want 1", result.RunningCount)
	}
	if result.Status != "ready" {
		t.Fatalf("Health().Status = %q, want ready", result.Status)
	}
}

func TestPutTerminalIngestRunIgnoresParentCancellation(t *testing.T) {
	parentCtx, cancel := context.WithCancel(context.Background())
	cancel()
	store := &stubRunStore{
		putFunc: func(ctx context.Context, _ graphstore.IngestRun) error {
			if err := ctx.Err(); err != nil {
				t.Fatalf("PutIngestRun context error = %v, want nil", err)
			}
			return nil
		},
	}
	run := graphstore.IngestRun{ID: "run-1", Status: graphstore.IngestRunStatusFailed}
	if err := New(nil, nil, nil, nil).putTerminalIngestRun(parentCtx, store, run); err != nil {
		t.Fatalf("putTerminalIngestRun() error = %v", err)
	}
	if len(store.putRuns) != 1 {
		t.Fatalf("PutIngestRun calls = %d, want 1", len(store.putRuns))
	}
	if got := store.putRuns[0].Status; got != graphstore.IngestRunStatusFailed {
		t.Fatalf("persisted status = %q, want failed", got)
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
