package graphingest

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"slices"
	"strings"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/graphstore"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/internal/sourceconfig"
	"github.com/writer/cerebro/internal/sourceops"
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
		if len(filter.RuntimeIDs) != 0 && !graphIngestStringInSlice(filter.RuntimeIDs, run.RuntimeID) {
			continue
		}
		if filter.Status != "" && run.Status != filter.Status {
			continue
		}
		runs = append(runs, run)
	}
	if filter.LatestByRuntime {
		runs = latestRunsByRuntime(runs)
	}
	if filter.Limit != 0 && len(runs) > filter.Limit {
		runs = runs[:filter.Limit]
	}
	return runs, nil
}

func graphIngestStringInSlice(values []string, needle string) bool {
	for _, value := range values {
		if value == needle {
			return true
		}
	}
	return false
}

type recordProjectorFunc func(*cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error)

func (f recordProjectorFunc) Project(_ context.Context, event *cerebrov1.EventEnvelope) (ports.ProjectionResult, error) {
	entities, links, err := f(event)
	return ports.ProjectionResult{
		EntitiesProjected: boundedUint32(len(entities)),
		LinksProjected:    boundedUint32(len(links)),
	}, err
}

func (f recordProjectorFunc) ProjectRecords(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return f(event)
}

type cleanupRecordProjector struct {
	records  func(*cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error)
	cleanup  func(*cerebrov1.EventEnvelope) ([]string, error)
	requests func(*cerebrov1.EventEnvelope) ([]ports.ProjectionCleanupRequest, error)
}

func (p cleanupRecordProjector) ProjectRecords(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return p.records(event)
}

func (p cleanupRecordProjector) ProjectCleanupRecords(event *cerebrov1.EventEnvelope) ([]string, error) {
	if p.cleanup == nil {
		return nil, nil
	}
	return p.cleanup(event)
}

func (p cleanupRecordProjector) ProjectCleanupRequests(event *cerebrov1.EventEnvelope) ([]ports.ProjectionCleanupRequest, error) {
	if p.requests == nil {
		return nil, nil
	}
	return p.requests(event)
}

type retractionProjector struct {
	recordProjectorFunc
	retractions []*ports.ProjectedLink
}

func (p retractionProjector) ProjectRetractions(*cerebrov1.EventEnvelope) ([]*ports.ProjectedLink, error) {
	return p.retractions, nil
}

type recordingProjectionGraphStore struct {
	entities        map[string]*ports.ProjectedEntity
	links           map[string]*ports.ProjectedLink
	upsertLinkErr   error
	deletedEntities map[string]struct{}
	deletedLinks    map[string]*ports.ProjectedLink
	cleanupRequests []ports.ProjectionCleanupRequest
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

type checkpointProjectionGraphStore struct {
	recordingProjectionGraphStore
	checkpoints map[string]graphstore.IngestCheckpoint
}

func (s *checkpointProjectionGraphStore) GetIngestCheckpoint(_ context.Context, id string) (graphstore.IngestCheckpoint, bool, error) {
	checkpoint, ok := s.checkpoints[id]
	return checkpoint, ok, nil
}

func (s *checkpointProjectionGraphStore) PutIngestCheckpoint(_ context.Context, checkpoint graphstore.IngestCheckpoint) error {
	if s.checkpoints == nil {
		s.checkpoints = map[string]graphstore.IngestCheckpoint{}
	}
	s.checkpoints[checkpoint.ID] = checkpoint
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

type cursorPagedSource struct {
	id    string
	pages [][]*cerebrov1.EventEnvelope
}

func (s *cursorPagedSource) Spec() *cerebrov1.SourceSpec {
	return &cerebrov1.SourceSpec{Id: s.id, Name: "Cursor Paged"}
}

func (s *cursorPagedSource) Check(context.Context, sourcecdk.Config) error { return nil }

func (s *cursorPagedSource) Discover(context.Context, sourcecdk.Config) ([]sourcecdk.URN, error) {
	return nil, nil
}

func (s *cursorPagedSource) Read(_ context.Context, _ sourcecdk.Config, cursor *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
	page := 0
	if cursor != nil && cursor.GetOpaque() == "page-1" {
		page = 1
	}
	pull := sourcecdk.Pull{Events: s.pages[page]}
	if page+1 < len(s.pages) {
		pull.NextCursor = &cerebrov1.SourceCursor{Opaque: "page-1"}
	}
	return pull, nil
}

func (s *recordingProjectionGraphStore) DeleteProjectedEntity(_ context.Context, urn string) error {
	if s.deletedEntities == nil {
		s.deletedEntities = map[string]struct{}{}
	}
	s.deletedEntities[urn] = struct{}{}
	delete(s.entities, urn)
	for key, link := range s.links {
		if link.FromURN == urn || link.ToURN == urn {
			delete(s.links, key)
		}
	}
	return nil
}

func (s *recordingProjectionGraphStore) DeleteProjectedLink(_ context.Context, link *ports.ProjectedLink) error {
	if link == nil {
		return nil
	}
	if s.deletedLinks == nil {
		s.deletedLinks = map[string]*ports.ProjectedLink{}
	}
	key := link.FromURN + "|" + link.Relation + "|" + link.ToURN
	s.deletedLinks[key] = link
	if s.links != nil {
		delete(s.links, key)
	}
	return nil
}

func (s *recordingProjectionGraphStore) CleanupProjectedEntities(_ context.Context, request ports.ProjectionCleanupRequest) (ports.ProjectionCleanupResult, error) {
	s.cleanupRequests = append(s.cleanupRequests, request)
	var result ports.ProjectionCleanupResult
	limit := projectionCleanupBatchLimit(request)
	for key, entity := range s.entities {
		if result.EntitiesDeleted >= limit {
			break
		}
		if !projectionCleanupTestMatches(request, entity) {
			continue
		}
		delete(s.entities, key)
		result.EntitiesDeleted++
	}
	for key, link := range s.links {
		if _, ok := s.entities[link.FromURN]; !ok {
			delete(s.links, key)
			result.LinksDeleted++
			continue
		}
		if _, ok := s.entities[link.ToURN]; !ok {
			delete(s.links, key)
			result.LinksDeleted++
		}
	}
	return result, nil
}

func projectionCleanupTestMatches(request ports.ProjectionCleanupRequest, entity *ports.ProjectedEntity) bool {
	if request.TenantID != "" && entity.TenantID != request.TenantID {
		return false
	}
	if request.SourceID != "" && entity.SourceID != request.SourceID {
		return false
	}
	if request.RuntimeID != "" && entity.RuntimeID != request.RuntimeID {
		return false
	}
	if len(request.EntityTypes) != 0 && !slices.Contains(request.EntityTypes, entity.EntityType) {
		return false
	}
	if len(request.URNPrefixes) == 0 {
		return true
	}
	for _, prefix := range request.URNPrefixes {
		if strings.HasPrefix(entity.URN, prefix) {
			return true
		}
	}
	return false
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
				FromURN:   "urn:cerebro:writer:github_code_repository:WriterInternal/k8s",
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
	}}, projector, nil)
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
	link := store.links["urn:cerebro:writer:github_code_repository:WriterInternal/k8s|belongs_to|urn:cerebro:writer:github_org:WriterInternal"]
	if link == nil {
		t.Fatal("coalesced repo->org link missing")
	}
	if got := link.Attributes["event_id"]; got != "event-2" {
		t.Fatalf("coalesced link event_id = %q, want latest event-2", got)
	}
}

func TestProjectResponseCoalescedDeletesCleanupRecords(t *testing.T) {
	staleURN := "urn:cerebro:writer:okta_resource:access_token:token-123"
	staleLink := &ports.ProjectedLink{
		TenantID: "writer",
		SourceID: "okta",
		FromURN:  "urn:cerebro:writer:okta_application:0oa-client",
		Relation: "acted_on",
		ToURN:    staleURN,
	}
	store := &recordingProjectionGraphStore{
		entities: map[string]*ports.ProjectedEntity{staleURN: {
			URN:        staleURN,
			TenantID:   "writer",
			SourceID:   "okta",
			RuntimeID:  "okta-audit-runtime",
			EntityType: "okta.resource",
			Label:      "token-123",
		}},
		links: map[string]*ports.ProjectedLink{"urn:cerebro:writer:okta_application:0oa-client|acted_on|" + staleURN: staleLink},
	}
	service := &Service{graphStore: store}
	projector := cleanupRecordProjector{
		records: func(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
			return []*ports.ProjectedEntity{{
					URN:        "urn:cerebro:writer:okta_application:0oa-client",
					TenantID:   event.GetTenantId(),
					SourceID:   event.GetSourceId(),
					RuntimeID:  event.GetAttributes()[ports.EventAttributeSourceRuntimeID],
					EntityType: "okta.application",
					Label:      "Production Client",
				}},
				[]*ports.ProjectedLink{{
					TenantID:  event.GetTenantId(),
					SourceID:  event.GetSourceId(),
					RuntimeID: event.GetAttributes()[ports.EventAttributeSourceRuntimeID],
					FromURN:   "urn:cerebro:writer:okta_actor:publicclientapp:0oa-client",
					Relation:  "acted_on",
					ToURN:     "urn:cerebro:writer:okta_application:0oa-client",
				}}, nil
		},
		cleanup: func(*cerebrov1.EventEnvelope) ([]string, error) {
			return []string{staleURN}, nil
		},
	}

	_, err := service.projectResponseCoalesced(context.Background(), sourceRequest{
		SourceID:  "okta",
		RuntimeID: "okta-audit-runtime",
		TenantID:  "writer",
	}, &cerebrov1.ReadSourceResponse{Events: []*cerebrov1.EventEnvelope{{
		Id:       "okta-oauth-grant",
		SourceId: "okta",
	}}}, projector, nil)
	if err != nil {
		t.Fatalf("projectResponseCoalesced() error = %v", err)
	}
	if _, ok := store.deletedEntities[staleURN]; !ok {
		t.Fatalf("cleanup entity %q was not deleted", staleURN)
	}
	if _, ok := store.entities[staleURN]; ok {
		t.Fatalf("cleanup entity %q still present", staleURN)
	}
	if _, ok := store.links["urn:cerebro:writer:okta_application:0oa-client|acted_on|"+staleURN]; ok {
		t.Fatalf("stale cleanup link still present")
	}
	if _, ok := store.links["urn:cerebro:writer:okta_actor:publicclientapp:0oa-client|acted_on|urn:cerebro:writer:okta_application:0oa-client"]; !ok {
		t.Fatalf("replacement durable link missing")
	}
}

func TestProjectResponseCoalescedRunsCleanupRequestsOnce(t *testing.T) {
	staleURN := "urn:cerebro:writer:okta_resource:access_token:token-123"
	appURN := "urn:cerebro:writer:okta_application:0oa-client"
	store := &recordingProjectionGraphStore{
		entities: map[string]*ports.ProjectedEntity{
			staleURN: {
				URN:        staleURN,
				TenantID:   "writer",
				SourceID:   "okta",
				RuntimeID:  "okta-audit-runtime",
				EntityType: "okta.resource",
				Label:      "token-123",
			},
			appURN: {
				URN:        appURN,
				TenantID:   "writer",
				SourceID:   "okta",
				RuntimeID:  "okta-audit-runtime",
				EntityType: "okta.application",
				Label:      "Production Client",
			},
		},
		links: map[string]*ports.ProjectedLink{
			appURN + "|acted_on|" + staleURN: {
				TenantID: "writer",
				SourceID: "okta",
				FromURN:  appURN,
				Relation: "acted_on",
				ToURN:    staleURN,
			},
		},
	}
	service := &Service{graphStore: store}
	projector := cleanupRecordProjector{
		records: func(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
			return []*ports.ProjectedEntity{{
				URN:        appURN,
				TenantID:   event.GetTenantId(),
				SourceID:   event.GetSourceId(),
				RuntimeID:  event.GetAttributes()[ports.EventAttributeSourceRuntimeID],
				EntityType: "okta.application",
				Label:      "Production Client",
			}}, nil, nil
		},
		requests: func(event *cerebrov1.EventEnvelope) ([]ports.ProjectionCleanupRequest, error) {
			return []ports.ProjectionCleanupRequest{{
				TenantID:    event.GetTenantId(),
				SourceID:    event.GetSourceId(),
				RuntimeID:   event.GetAttributes()[ports.EventAttributeSourceRuntimeID],
				EntityTypes: []string{"okta.resource"},
				URNPrefixes: []string{"urn:cerebro:writer:okta_resource:access_token:"},
				Limit:       1000,
			}}, nil
		},
	}

	_, err := service.projectResponseCoalesced(context.Background(), sourceRequest{
		SourceID:  "okta",
		RuntimeID: "okta-audit-runtime",
		TenantID:  "writer",
	}, &cerebrov1.ReadSourceResponse{Events: []*cerebrov1.EventEnvelope{
		{Id: "okta-oauth-grant-1", SourceId: "okta"},
		{Id: "okta-oauth-grant-2", SourceId: "okta"},
	}}, projector, nil)
	if err != nil {
		t.Fatalf("projectResponseCoalesced() error = %v", err)
	}
	if got := len(store.cleanupRequests); got != 1 {
		t.Fatalf("cleanup requests = %d, want 1 deduped request", got)
	}
	if _, ok := store.entities[staleURN]; ok {
		t.Fatalf("stale cleanup entity %q still present", staleURN)
	}
	if _, ok := store.links[appURN+"|acted_on|"+staleURN]; ok {
		t.Fatalf("stale cleanup link still present")
	}
	if _, ok := store.entities[appURN]; !ok {
		t.Fatalf("durable app entity was deleted")
	}
}

func TestProjectResponseCoalescedSkipsCompletedCleanupRequests(t *testing.T) {
	store := &recordingProjectionGraphStore{
		entities: map[string]*ports.ProjectedEntity{
			"urn:cerebro:writer:okta_resource:access_token:token-123": {
				URN:        "urn:cerebro:writer:okta_resource:access_token:token-123",
				TenantID:   "writer",
				SourceID:   "okta",
				RuntimeID:  "okta-audit-runtime",
				EntityType: "okta.resource",
				Label:      "token-123",
			},
		},
	}
	service := &Service{graphStore: store}
	projector := cleanupRecordProjector{
		records: func(*cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
			return nil, nil, nil
		},
		requests: func(event *cerebrov1.EventEnvelope) ([]ports.ProjectionCleanupRequest, error) {
			return []ports.ProjectionCleanupRequest{{
				TenantID:    event.GetTenantId(),
				SourceID:    event.GetSourceId(),
				RuntimeID:   event.GetAttributes()[ports.EventAttributeSourceRuntimeID],
				EntityTypes: []string{"okta.resource"},
				URNPrefixes: []string{"urn:cerebro:writer:okta_resource:access_token:"},
				Limit:       1000,
			}}, nil
		},
	}
	completedCleanupRequests := map[string]struct{}{}
	request := sourceRequest{SourceID: "okta", RuntimeID: "okta-audit-runtime", TenantID: "writer"}
	response := func(id string) *cerebrov1.ReadSourceResponse {
		return &cerebrov1.ReadSourceResponse{Events: []*cerebrov1.EventEnvelope{{Id: id, SourceId: "okta"}}}
	}

	if _, err := service.projectResponseCoalesced(context.Background(), request, response("okta-oauth-grant-page-1"), projector, completedCleanupRequests); err != nil {
		t.Fatalf("projectResponseCoalesced(page 1) error = %v", err)
	}
	if _, err := service.projectResponseCoalesced(context.Background(), request, response("okta-oauth-grant-page-2"), projector, completedCleanupRequests); err != nil {
		t.Fatalf("projectResponseCoalesced(page 2) error = %v", err)
	}
	if got := len(store.cleanupRequests); got != 1 {
		t.Fatalf("cleanup requests = %d, want 1 across pages", got)
	}
}

func TestProjectResponseCoalescedRunsCleanupRequestsUntilExhausted(t *testing.T) {
	store := &recordingProjectionGraphStore{
		entities: map[string]*ports.ProjectedEntity{
			"urn:cerebro:writer:okta_resource:access_token:token-1": {
				URN:        "urn:cerebro:writer:okta_resource:access_token:token-1",
				TenantID:   "writer",
				SourceID:   "okta",
				RuntimeID:  "okta-audit-runtime",
				EntityType: "okta.resource",
				Label:      "token-1",
			},
			"urn:cerebro:writer:okta_resource:access_token:token-2": {
				URN:        "urn:cerebro:writer:okta_resource:access_token:token-2",
				TenantID:   "writer",
				SourceID:   "okta",
				RuntimeID:  "okta-audit-runtime",
				EntityType: "okta.resource",
				Label:      "token-2",
			},
		},
	}
	service := &Service{graphStore: store}
	projector := cleanupRecordProjector{
		records: func(*cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
			return nil, nil, nil
		},
		requests: func(event *cerebrov1.EventEnvelope) ([]ports.ProjectionCleanupRequest, error) {
			return []ports.ProjectionCleanupRequest{{
				TenantID:    event.GetTenantId(),
				SourceID:    event.GetSourceId(),
				RuntimeID:   event.GetAttributes()[ports.EventAttributeSourceRuntimeID],
				EntityTypes: []string{"okta.resource"},
				URNPrefixes: []string{"urn:cerebro:writer:okta_resource:access_token:"},
				Limit:       1,
			}}, nil
		},
	}

	_, err := service.projectResponseCoalesced(context.Background(), sourceRequest{
		SourceID:  "okta",
		RuntimeID: "okta-audit-runtime",
		TenantID:  "writer",
	}, &cerebrov1.ReadSourceResponse{Events: []*cerebrov1.EventEnvelope{{
		Id:       "okta-oauth-grant",
		SourceId: "okta",
	}}}, projector, nil)
	if err != nil {
		t.Fatalf("projectResponseCoalesced() error = %v", err)
	}
	if got := len(store.cleanupRequests); got != 3 {
		t.Fatalf("cleanup calls = %d, want 3 calls to confirm exhaustion", got)
	}
	if len(store.entities) != 0 {
		t.Fatalf("store retained %d cleanup entities", len(store.entities))
	}
}

func TestProjectResponseCoalescedDeletesProjectedRetractions(t *testing.T) {
	staleLink := &ports.ProjectedLink{
		TenantID: "writer",
		SourceID: "kolide",
		FromURN:  "urn:cerebro:writer:kolide_device:device-1",
		Relation: "owned_by",
		ToURN:    "urn:cerebro:writer:identity:login:user-1",
	}
	key := staleLink.FromURN + "|" + staleLink.Relation + "|" + staleLink.ToURN
	store := &recordingProjectionGraphStore{links: map[string]*ports.ProjectedLink{key: staleLink}}
	service := &Service{graphStore: store}
	projector := retractionProjector{
		recordProjectorFunc: func(*cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
			return nil, nil, nil
		},
		retractions: []*ports.ProjectedLink{staleLink},
	}

	_, err := service.projectResponseCoalesced(context.Background(), sourceRequest{
		SourceID:  "kolide",
		RuntimeID: "kolide-runtime",
		TenantID:  "writer",
	}, &cerebrov1.ReadSourceResponse{Events: []*cerebrov1.EventEnvelope{{
		Id:       "kolide-device",
		SourceId: "kolide",
	}}}, projector, nil)
	if err != nil {
		t.Fatalf("projectResponseCoalesced() error = %v", err)
	}
	if _, ok := store.deletedLinks[key]; !ok {
		t.Fatalf("stale link was not deleted: %#v", store.deletedLinks)
	}
	if _, ok := store.links[key]; ok {
		t.Fatalf("stale link remains after deletion")
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
				ToURN:     "urn:cerebro:writer:github_code_repository:writer/cerebro",
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
	}}, projector, nil)
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
	link := store.links["urn:cerebro:writer:github_user:alice|acted_on|urn:cerebro:writer:github_code_repository:writer/cerebro"]
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

func TestIngestSourceReportsProgressAfterEachPersistedPage(t *testing.T) {
	registry, err := sourcecdk.NewRegistry(&cursorPagedSource{
		id: "paged",
		pages: [][]*cerebrov1.EventEnvelope{
			{{Id: "event-1", SourceId: "paged"}},
			{{Id: "event-2", SourceId: "paged"}},
		},
	})
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	store := &checkpointProjectionGraphStore{}
	service := &Service{
		sourceService: sourceops.New(registry),
		graphStore:    store,
		projector: recordProjectorFunc(func(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
			return []*ports.ProjectedEntity{{
				URN:        "urn:cerebro:writer:paged:" + event.GetId(),
				TenantID:   event.GetTenantId(),
				SourceID:   event.GetSourceId(),
				EntityType: "paged.entity",
				Label:      event.GetId(),
			}}, nil, nil
		}),
	}
	var snapshots []IngestResult
	result, err := service.ingestSource(context.Background(), sourceRequest{
		SourceID:          "paged",
		RuntimeID:         "runtime-1",
		TenantID:          "writer",
		PageLimit:         2,
		CheckpointEnabled: true,
		CheckpointID:      "checkpoint-1",
	}, func(progress *IngestResult) {
		snapshots = append(snapshots, *progress)
	})
	if err != nil {
		t.Fatalf("ingestSource() error = %v", err)
	}
	if result.PagesRead != 2 || result.EventsRead != 2 || result.EntitiesProjected != 2 {
		t.Fatalf("result pages/events/entities = %d/%d/%d, want 2/2/2", result.PagesRead, result.EventsRead, result.EntitiesProjected)
	}
	if len(snapshots) != 2 {
		t.Fatalf("progress snapshots = %d, want 2", len(snapshots))
	}
	if snapshots[0].PagesRead != 1 || snapshots[0].EventsRead != 1 || !snapshots[0].CheckpointPersisted {
		t.Fatalf("first progress = %#v, want one persisted page", snapshots[0])
	}
	if snapshots[1].PagesRead != 2 || snapshots[1].EventsRead != 2 || !snapshots[1].CheckpointComplete {
		t.Fatalf("second progress = %#v, want completed second page", snapshots[1])
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

func TestIngestSourceCanResetCompletedCheckpoint(t *testing.T) {
	registry, err := sourcecdk.NewRegistry(&singlePageSource{
		id: "checkpointed",
		events: []*cerebrov1.EventEnvelope{{
			Id:       "event-1",
			SourceId: "checkpointed",
		}},
	})
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	store := &checkpointProjectionGraphStore{
		checkpoints: map[string]graphstore.IngestCheckpoint{
			"checkpoint-1": {ID: "checkpoint-1", Completed: true},
		},
	}
	projector := recordProjectorFunc(func(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
		return []*ports.ProjectedEntity{{
			URN:        "urn:cerebro:writer:checkpointed:event-1",
			TenantID:   event.GetTenantId(),
			SourceID:   event.GetSourceId(),
			RuntimeID:  event.GetAttributes()[ports.EventAttributeSourceRuntimeID],
			EntityType: "checkpointed.event",
			Label:      event.GetId(),
		}}, nil, nil
	})
	service := New(registry, nil, projector, store)

	freshResult, err := service.ingestSource(context.Background(), sourceRequest{
		SourceID:          "checkpointed",
		RuntimeID:         "runtime-1",
		TenantID:          "writer",
		PageLimit:         1,
		CheckpointEnabled: true,
		CheckpointID:      "checkpoint-1",
	})
	if err != nil {
		t.Fatalf("ingestSource(default checkpoint) error = %v", err)
	}
	if !freshResult.CheckpointAlreadyFresh || freshResult.EventsRead != 0 {
		t.Fatalf("default checkpoint result fresh=%v events=%d, want already fresh with no reads", freshResult.CheckpointAlreadyFresh, freshResult.EventsRead)
	}

	resetResult, err := service.ingestSource(context.Background(), sourceRequest{
		SourceID:                 "checkpointed",
		RuntimeID:                "runtime-1",
		TenantID:                 "writer",
		PageLimit:                1,
		CheckpointEnabled:        true,
		CheckpointID:             "checkpoint-1",
		ResetCompletedCheckpoint: true,
	})
	if err != nil {
		t.Fatalf("ingestSource(reset completed checkpoint) error = %v", err)
	}
	if resetResult.CheckpointAlreadyFresh {
		t.Fatal("reset completed checkpoint was treated as already fresh")
	}
	if resetResult.PagesRead != 1 || resetResult.EventsRead != 1 || !resetResult.CheckpointPersisted {
		t.Fatalf("reset checkpoint result pages=%d events=%d persisted=%v, want 1/1/persisted", resetResult.PagesRead, resetResult.EventsRead, resetResult.CheckpointPersisted)
	}
}

func TestResetCompletedCheckpointClearsStoredFreshnessBeforeProjection(t *testing.T) {
	projectionErr := errors.New("projection failed")
	registry, err := sourcecdk.NewRegistry(&singlePageSource{
		id: "checkpointed",
		events: []*cerebrov1.EventEnvelope{{
			Id:       "event-1",
			SourceId: "checkpointed",
		}},
	})
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	store := &checkpointProjectionGraphStore{
		checkpoints: map[string]graphstore.IngestCheckpoint{
			"checkpoint-1": {ID: "checkpoint-1", Completed: true},
		},
	}
	projector := recordProjectorFunc(func(*cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
		return nil, nil, projectionErr
	})
	service := New(registry, nil, projector, store)

	result, err := service.ingestSource(context.Background(), sourceRequest{
		SourceID:                 "checkpointed",
		RuntimeID:                "runtime-1",
		TenantID:                 "writer",
		PageLimit:                1,
		CheckpointEnabled:        true,
		CheckpointID:             "checkpoint-1",
		ResetCompletedCheckpoint: true,
	})
	if !errors.Is(err, projectionErr) {
		t.Fatalf("ingestSource() error = %v, want %v", err, projectionErr)
	}
	if result.CheckpointPersisted {
		t.Fatal("failed projection should not report a persisted page checkpoint")
	}
	stored := store.checkpoints["checkpoint-1"]
	if stored.Completed {
		t.Fatal("stored checkpoint remained completed after reset marker")
	}

	freshCheck := &IngestResult{}
	var cursor *cerebrov1.SourceCursor
	if _, err := service.prepareCheckpoint(context.Background(), sourceRequest{
		SourceID:          "checkpointed",
		RuntimeID:         "runtime-1",
		TenantID:          "writer",
		PageLimit:         1,
		CheckpointEnabled: true,
		CheckpointID:      "checkpoint-1",
	}, freshCheck, &cursor); err != nil {
		t.Fatalf("prepareCheckpoint() error = %v", err)
	}
	if freshCheck.CheckpointAlreadyFresh {
		t.Fatal("cleared checkpoint was still treated as already fresh")
	}
}

func TestResetCheckpointClearsPartialCheckpointBeforeProjection(t *testing.T) {
	projectionErr := errors.New("projection failed")
	registry, err := sourcecdk.NewRegistry(&singlePageSource{
		id: "checkpointed",
		events: []*cerebrov1.EventEnvelope{{
			Id:       "event-1",
			SourceId: "checkpointed",
		}},
	})
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	store := &checkpointProjectionGraphStore{
		checkpoints: map[string]graphstore.IngestCheckpoint{
			"checkpoint-1": {ID: "checkpoint-1", CursorOpaque: "2", Completed: false, PagesRead: 1, EventsRead: 1},
		},
	}
	projector := recordProjectorFunc(func(*cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
		return nil, nil, projectionErr
	})
	service := New(registry, nil, projector, store)

	result, err := service.ingestSource(context.Background(), sourceRequest{
		SourceID:          "checkpointed",
		RuntimeID:         "runtime-1",
		TenantID:          "writer",
		PageLimit:         1,
		CheckpointEnabled: true,
		CheckpointID:      "checkpoint-1",
		ResetCheckpoint:   true,
	})
	if !errors.Is(err, projectionErr) {
		t.Fatalf("ingestSource() error = %v, want %v", err, projectionErr)
	}
	if result.CheckpointPersisted {
		t.Fatal("failed projection should not report a persisted page checkpoint")
	}
	stored := store.checkpoints["checkpoint-1"]
	if stored.CursorOpaque != "" || stored.Completed || stored.PagesRead != 0 || stored.EventsRead != 0 {
		t.Fatalf("stored checkpoint = %#v, want cleared reset marker", stored)
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

func TestHealthEmitsTelemetry(t *testing.T) {
	store := &stubRunStore{
		runs: []graphstore.IngestRun{
			{ID: "failed-1", Status: graphstore.IngestRunStatusFailed},
			{ID: "running-1", Status: graphstore.IngestRunStatusRunning},
		},
	}
	stderr := captureGraphIngestStderr(t, func() {
		result, err := New(nil, nil, nil, store).Health(context.Background(), 1)
		if err != nil {
			t.Fatalf("Health() error = %v", err)
		}
		if result.Status != "degraded" {
			t.Fatalf("Health().Status = %q, want degraded", result.Status)
		}
	})

	payload := graphIngestTelemetryPayload(t, stderr, "graph.ingest_health")
	for key, want := range map[string]any{
		"kind":          "span_end",
		"name":          "graph.ingest_health",
		"status":        "completed",
		"limit":         float64(1),
		"health_status": "degraded",
		"failed_count":  float64(1),
		"running_count": float64(1),
	} {
		if got := payload[key]; got != want {
			t.Fatalf("telemetry %s = %#v, want %#v; payload=%#v", key, got, want, payload)
		}
	}
	if _, ok := payload["duration_ms"].(float64); !ok {
		t.Fatalf("telemetry duration_ms = %#v, want number; payload=%#v", payload["duration_ms"], payload)
	}
}

func TestListRunsTelemetryRecordsInvalidRequest(t *testing.T) {
	stderr := captureGraphIngestStderr(t, func() {
		_, err := New(nil, nil, nil, &stubRunStore{}).ListRuns(context.Background(), graphstore.IngestRunFilter{Status: "bogus"})
		if !errors.Is(err, ErrInvalidRequest) {
			t.Fatalf("ListRuns() error = %v, want ErrInvalidRequest", err)
		}
	})

	payload := graphIngestTelemetryPayload(t, stderr, "graph.ingest_list_runs")
	if got := payload["status"]; got != "failed" {
		t.Fatalf("telemetry status = %#v, want failed; payload=%#v", got, payload)
	}
	if got := payload["error_kind"]; got != "invalid_request" {
		t.Fatalf("telemetry error_kind = %#v, want invalid_request; payload=%#v", got, payload)
	}
	if strings.Contains(stderr, "bogus") {
		t.Fatalf("ListRuns telemetry leaked raw invalid status value: %s", stderr)
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

func TestFinishRunClassifiesErrorsWithoutRawSecret(t *testing.T) {
	run := graphstore.IngestRun{ID: "run-1", Status: graphstore.IngestRunStatusRunning}
	finished := finishRun(run, nil, graphstore.IngestRunStatusFailed, errors.New("provider failed credential=fake-sensitive-value"))
	if finished.Error != "ingest_failed" {
		t.Fatalf("finishRun error = %q, want ingest_failed", finished.Error)
	}
	if strings.Contains(finished.Error, "fake-sensitive-value") || strings.Contains(finished.Error, "credential=") {
		t.Fatalf("finishRun leaked raw error: %q", finished.Error)
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

func captureGraphIngestStderr(t *testing.T, fn func()) string {
	t.Helper()
	oldStderr := os.Stderr
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe stderr: %v", err)
	}
	os.Stderr = writer
	defer func() {
		os.Stderr = oldStderr
	}()
	fn()
	if err := writer.Close(); err != nil {
		t.Fatalf("close stderr writer: %v", err)
	}
	payload, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("read stderr: %v", err)
	}
	return string(payload)
}

func graphIngestTelemetryPayload(t *testing.T, stderr string, name string) map[string]any {
	t.Helper()
	lines := strings.Split(strings.TrimSpace(stderr), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if strings.TrimSpace(lines[i]) == "" {
			continue
		}
		payload := map[string]any{}
		if err := json.Unmarshal([]byte(lines[i]), &payload); err != nil {
			t.Fatalf("unmarshal telemetry payload %q: %v", lines[i], err)
		}
		if payload["kind"] == "span_end" && payload["name"] == name {
			return payload
		}
	}
	t.Fatalf("telemetry span_end %q not found in stderr: %s", name, stderr)
	return nil
}
