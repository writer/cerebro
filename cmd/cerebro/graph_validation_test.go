//go:build cgo

package main

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	configpkg "github.com/writer/cerebro/internal/config"
	"github.com/writer/cerebro/internal/graphingest"
	graphstorekuzu "github.com/writer/cerebro/internal/graphstore/kuzu"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/primitives"
	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/internal/sourceops"
	"github.com/writer/cerebro/internal/sourceprojection"
)

func TestGraphKuzuCLIValidationFlow(t *testing.T) {
	ctx := context.Background()
	graphPath := filepath.Join(t.TempDir(), "graph")
	store, err := graphstorekuzu.Open(configpkg.GraphStoreConfig{
		Driver:   configpkg.GraphStoreDriverKuzu,
		KuzuPath: graphPath,
	})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	source, err := validationFixtureSource()
	if err != nil {
		t.Fatalf("validationFixtureSource() error = %v", err)
	}
	registry, err := sourcecdk.NewRegistry(source)
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	projector := sourceprojection.New(nil, store)
	options := graphIngestOptions{
		SourceID:          "github",
		SourceConfig:      map[string]string{"family": "audit"},
		TenantID:          "writer",
		PageLimit:         1,
		CheckpointEnabled: true,
		CheckpointID:      "validation-github-audit",
	}

	first, err := ingestGraph(ctx, sourceops.New(registry), projector, store, options)
	if err != nil {
		t.Fatalf("ingestGraph(first) error = %v", err)
	}
	if first.EventsRead != 1 || !first.CheckpointPersisted || first.NextCursor == "" {
		t.Fatalf("first ingest result = %#v, want one event, persisted checkpoint, and next cursor", first)
	}
	second, err := ingestGraph(ctx, sourceops.New(registry), projector, store, options)
	if err != nil {
		t.Fatalf("ingestGraph(second) error = %v", err)
	}
	if second.EventsRead != 1 || !second.CheckpointResumed || !second.CheckpointPersisted || !second.CheckpointComplete {
		t.Fatalf("second ingest result = %#v, want resumed completed checkpoint", second)
	}

	identityURN := "urn:cerebro:writer:identity:email:alice@writer.com"
	neighborhood, err := store.GetEntityNeighborhood(ctx, identityURN, 10)
	if err != nil {
		t.Fatalf("GetEntityNeighborhood() error = %v", err)
	}
	if !neighborhoodHasEvidence(neighborhood.Relations, "source_event_id", "github-audit-validation-2") {
		t.Fatalf("neighborhood relations missing latest source_event_id evidence: %#v", neighborhood.Relations)
	}
	patterns, err := store.PathPatterns(ctx, 5)
	if err != nil {
		t.Fatalf("PathPatterns() error = %v", err)
	}
	if len(patterns) == 0 {
		t.Fatal("PathPatterns() returned zero patterns")
	}
	checks, err := store.IntegrityChecks(ctx)
	if err != nil {
		t.Fatalf("IntegrityChecks() error = %v", err)
	}
	for _, check := range checks {
		if !check.Passed {
			t.Fatalf("integrity check failed: %#v", check)
		}
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	t.Setenv("CEREBRO_GRAPH_STORE_DRIVER", configpkg.GraphStoreDriverKuzu)
	t.Setenv("CEREBRO_KUZU_PATH", graphPath)
	for _, args := range [][]string{
		{"counts"},
		{"neighborhood", "root_urn=" + identityURN, "limit=10"},
		{"paths", "limit=5"},
		{"integrity"},
	} {
		if err := runGraph(args); err != nil {
			t.Fatalf("runGraph(%v) error = %v", args, err)
		}
	}
}

func TestGraphRuntimeIngestRecordsStatus(t *testing.T) {
	ctx := context.Background()
	store, err := graphstorekuzu.Open(configpkg.GraphStoreConfig{
		Driver:   configpkg.GraphStoreDriverKuzu,
		KuzuPath: filepath.Join(t.TempDir(), "graph"),
	})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	t.Cleanup(func() {
		if closeErr := store.Close(); closeErr != nil {
			t.Fatalf("Close() error = %v", closeErr)
		}
	})
	source, err := validationFixtureSourceWithID("validation")
	if err != nil {
		t.Fatalf("validationFixtureSourceWithID() error = %v", err)
	}
	registry, err := sourcecdk.NewRegistry(source)
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	runtimeStore := &validationRuntimeStore{runtimes: map[string]*cerebrov1.SourceRuntime{
		"writer-validation": {
			Id:       "writer-validation",
			SourceId: "validation",
			TenantId: "writer",
			Config:   map[string]string{"family": "audit"},
		},
		"writer-validation-failing": {
			Id:       "writer-validation-failing",
			SourceId: "validation",
			TenantId: "writer",
			Config:   map[string]string{"family": "missing"},
		},
	}}
	projector := sourceprojection.New(nil, store)
	service := graphingest.New(registry, runtimeStore, projector, store)
	result, err := service.RunRuntime(ctx, graphingest.RuntimeRequest{
		RuntimeID:    "writer-validation",
		PageLimit:    2,
		CheckpointID: "runtime-validation",
		Trigger:      "test",
	})
	if err != nil {
		t.Fatalf("RunRuntime() error = %v", err)
	}
	if result.Run.Status != "completed" || result.Ingest.EventsRead != 2 {
		t.Fatalf("RunRuntime() = %#v, want completed two-event run", result)
	}
	completed, err := store.ListIngestRuns(ctx, graphstorekuzu.IngestRunFilter{RuntimeID: "writer-validation", Status: "completed", Limit: 10})
	if err != nil {
		t.Fatalf("ListIngestRuns(completed) error = %v", err)
	}
	if len(completed) != 1 || completed[0].CheckpointID != "runtime-validation" {
		t.Fatalf("completed runs = %#v, want runtime-validation checkpoint", completed)
	}

	failedResult, err := service.RunRuntime(ctx, graphingest.RuntimeRequest{
		RuntimeID: "writer-validation-failing",
		PageLimit: defaultGraphIngestPageLimit,
		Trigger:   "test",
	})
	if err == nil {
		t.Fatal("RunRuntime(failing) error = nil, want non-nil")
	}
	if failedResult.Run.Status != "failed" || failedResult.Run.Error == "" {
		t.Fatalf("failed ingest result = %#v, want failed run with error", failedResult)
	}
}

func validationFixtureSource() (sourcecdk.Source, error) {
	return validationFixtureSourceWithID("github")
}

func validationFixtureSourceWithID(sourceID string) (sourcecdk.Source, error) {
	events := []*primitives.Event{
		validationGitHubAuditEvent("github-audit-validation-1"),
		validationGitHubAuditEvent("github-audit-validation-2"),
	}
	return sourcecdk.NewFixtureSource(sourcecdk.FixtureSourceOptions{
		Spec:          &cerebrov1.SourceSpec{Id: sourceID, Name: "Graph validation fixture"},
		DefaultFamily: "audit",
		Families: []sourcecdk.FixtureFamily{{
			Name:   "audit",
			Events: events,
		}},
	})
}

func validationGitHubAuditEvent(id string) *primitives.Event {
	return &primitives.Event{
		Id:         id,
		TenantId:   "github-tenant",
		SourceId:   "github",
		Kind:       "github.audit",
		OccurredAt: timestamppb.New(time.Date(2026, 4, 29, 0, 0, 0, 0, time.UTC)),
		SchemaRef:  "github/audit/v1",
		Payload:    []byte(`{}`),
		Attributes: map[string]string{
			"actor":                    "alice",
			"external_identity_nameid": "alice@writer.com",
			"org":                      "writer",
			"repo":                     "writer/cerebro",
			"resource_id":              "writer/cerebro",
			"resource_type":            "repository",
		},
	}
}

func neighborhoodHasEvidence(relations []*ports.NeighborhoodRelation, key string, value string) bool {
	for _, relation := range relations {
		if relation != nil && relation.Attributes[key] == value {
			return true
		}
	}
	return false
}

type validationRuntimeStore struct {
	runtimes map[string]*cerebrov1.SourceRuntime
}

func (s *validationRuntimeStore) Ping(context.Context) error {
	return nil
}

func (s *validationRuntimeStore) PutSourceRuntime(_ context.Context, runtime *cerebrov1.SourceRuntime) error {
	s.runtimes[runtime.GetId()] = runtime
	return nil
}

func (s *validationRuntimeStore) GetSourceRuntime(_ context.Context, id string) (*cerebrov1.SourceRuntime, error) {
	runtime, ok := s.runtimes[id]
	if !ok {
		return nil, ports.ErrSourceRuntimeNotFound
	}
	return runtime, nil
}
