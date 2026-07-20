package main

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/graphstore"
	"github.com/writer/cerebro/internal/ports"
)

func TestCheckGraphHealthPasses(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 5, 31, 12, 0, 0, 0, time.UTC)
	store := graphHealthFixtureStore(t, now)

	result, err := checkGraphHealth(ctx, store, graphHealthOptions{
		IngestLimit:        10,
		MaxRunningMinutes:  60,
		RequiredRelations:  []string{"belongs_to"},
		DeclaredRuntimeIDs: []string{"aws-runtime"},
	}, now)
	if err != nil {
		t.Fatalf("checkGraphHealth() error = %v", err)
	}
	if result.Status != "passed" {
		t.Fatalf("health status = %q, want passed", result.Status)
	}
	if result.Counts.Nodes != 2 || result.Counts.Relations != 1 || result.RelationCounts["belongs_to"] != 1 {
		t.Fatalf("health counts = %#v relation_counts=%#v, want populated graph", result.Counts, result.RelationCounts)
	}
	if result.Ingest.CurrentRuntimeCount != 1 {
		t.Fatalf("current runtime count = %d, want 1", result.Ingest.CurrentRuntimeCount)
	}
	if result.Topology == nil || result.Topology.SourcesOnly != 1 || result.Topology.SinksOnly != 1 || result.Topology.Isolated != 0 {
		t.Fatalf("topology = %#v, want sources_only=1 sinks_only=1 isolated=0", result.Topology)
	}
	if len(result.Warnings) != 0 {
		t.Fatalf("warnings = %#v, want none for report-only topology", result.Warnings)
	}
}

func TestCheckGraphHealthReportsTopologyAndRelationDrift(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 5, 31, 12, 0, 0, 0, time.UTC)
	store := graphHealthFixtureStore(t, now)
	if err := store.UpsertProjectedEntity(ctx, &ports.ProjectedEntity{
		URN:        "urn:cerebro:writer:identity:orphan",
		TenantID:   "writer",
		SourceID:   "test",
		EntityType: "identity",
		Label:      "orphan",
	}); err != nil {
		t.Fatalf("UpsertProjectedEntity(orphan) error = %v", err)
	}

	result, err := checkGraphHealth(ctx, store, graphHealthOptions{
		IngestLimit:       10,
		MaxRunningMinutes: 60,
		RequiredRelations: []string{"belongs_to"},
		ReportRelations:   []string{"belongs_to", "can_assume"},
		MaxIsolatedRatio:  0.1,
	}, now)
	if err != nil {
		t.Fatalf("checkGraphHealth() error = %v", err)
	}
	if result.Status != "passed" {
		t.Fatalf("health status = %q, want passed (topology and drift are non-blocking)", result.Status)
	}
	if result.Topology == nil || result.Topology.Isolated != 1 {
		t.Fatalf("topology = %#v, want isolated=1", result.Topology)
	}
	if result.ReportedRelationCounts["belongs_to"] != 1 || result.ReportedRelationCounts["can_assume"] != 0 {
		t.Fatalf("reported relation counts = %#v, want belongs_to=1 can_assume=0", result.ReportedRelationCounts)
	}
	joined := strings.Join(result.Warnings, "; ")
	if !strings.Contains(joined, "isolated-node ratio") {
		t.Fatalf("warnings = %#v, want isolated-node ratio warning", result.Warnings)
	}
	if !strings.Contains(joined, "zero edges for 1 reported relation(s): can_assume") {
		t.Fatalf("warnings = %#v, want can_assume drift warning", result.Warnings)
	}
}

func TestCheckGraphHealthFailsLatestFailedRunUnlessTransientAllowed(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 5, 31, 12, 0, 0, 0, time.UTC)
	store := graphHealthFixtureStore(t, now)
	if err := store.PutIngestRun(ctx, graphstore.IngestRun{
		ID:           "run-2",
		RuntimeID:    "aws-runtime",
		SourceID:     "aws",
		Status:       graphstore.IngestRunStatusFailed,
		StartedAt:    now.Add(-time.Minute).Format(time.RFC3339Nano),
		FinishedAt:   now.Format(time.RFC3339Nano),
		Error:        "context deadline exceeded",
		EventsRead:   1,
		PagesRead:    1,
		CheckpointID: "aws-runtime",
	}); err != nil {
		t.Fatalf("PutIngestRun(failed) error = %v", err)
	}

	strict, err := checkGraphHealth(ctx, store, graphHealthOptions{
		IngestLimit:       10,
		MaxRunningMinutes: 60,
		RequiredRelations: []string{"belongs_to"},
	}, now)
	if err == nil {
		t.Fatal("checkGraphHealth(strict) error = nil, want latest failed run error")
	}
	if strict.Status != "failed" || len(strict.Ingest.FailedRuns) != 1 || !strings.Contains(strings.Join(strict.Failures, "; "), "latest graph ingest run failed") {
		t.Fatalf("strict health = %#v, want failed latest-run detail", strict)
	}

	allowed, err := checkGraphHealth(ctx, store, graphHealthOptions{
		IngestLimit:                  10,
		MaxRunningMinutes:            60,
		RequiredRelations:            []string{"belongs_to"},
		AllowTransientSourceFailures: true,
	}, now)
	if err != nil {
		t.Fatalf("checkGraphHealth(allowed transient) error = %v", err)
	}
	if allowed.Status != "passed" || len(allowed.Ingest.IgnoredTransientFailedRuns) != 1 || len(allowed.Warnings) == 0 {
		t.Fatalf("allowed health = %#v, want ignored transient warning", allowed)
	}
}

func TestCheckGraphHealthAcceptsLegacyCompletedRunWithoutCheckpointState(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 5, 31, 12, 0, 0, 0, time.UTC)
	store := graphHealthFixtureStore(t, now)
	run, ok, err := store.GetIngestRun(ctx, "run-1")
	if err != nil || !ok {
		t.Fatalf("GetIngestRun(run-1) = %#v, %v, %v", run, ok, err)
	}
	run.CheckpointComplete = false
	run.CheckpointCompleteKnown = false
	if err := store.PutIngestRun(ctx, run); err != nil {
		t.Fatalf("PutIngestRun(legacy completed) error = %v", err)
	}

	result, err := checkGraphHealth(ctx, store, graphHealthOptions{
		IngestLimit:       10,
		MaxRunningMinutes: 60,
		RequiredRelations: []string{"belongs_to"},
	}, now)
	if err != nil {
		t.Fatalf("checkGraphHealth() error = %v", err)
	}
	if result.Status != "passed" || len(result.Ingest.IncompleteRuns) != 0 {
		t.Fatalf("health result = %#v, want legacy completed run accepted", result)
	}
}

func TestCheckGraphHealthUsesLegacyCompletedRunAsTransientFailureHistory(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 5, 31, 12, 0, 0, 0, time.UTC)
	store := graphHealthFixtureStore(t, now)
	legacy, ok, err := store.GetIngestRun(ctx, "run-1")
	if err != nil || !ok {
		t.Fatalf("GetIngestRun(run-1) = %#v, %v, %v", legacy, ok, err)
	}
	legacy.CheckpointComplete = false
	legacy.CheckpointCompleteKnown = false
	if err := store.PutIngestRun(ctx, legacy); err != nil {
		t.Fatalf("PutIngestRun(legacy completed) error = %v", err)
	}
	if err := store.PutIngestRun(ctx, graphstore.IngestRun{
		ID:         "run-2",
		RuntimeID:  "aws-runtime",
		SourceID:   "aws",
		Status:     graphstore.IngestRunStatusFailed,
		StartedAt:  now.Add(-time.Minute).Format(time.RFC3339Nano),
		FinishedAt: now.Format(time.RFC3339Nano),
		Error:      "context deadline exceeded",
	}); err != nil {
		t.Fatalf("PutIngestRun(failed) error = %v", err)
	}

	result, err := checkGraphHealth(ctx, store, graphHealthOptions{
		IngestLimit:                  10,
		MaxRunningMinutes:            60,
		RequiredRelations:            []string{"belongs_to"},
		AllowTransientSourceFailures: true,
	}, now)
	if err != nil {
		t.Fatalf("checkGraphHealth() error = %v", err)
	}
	if result.Status != "passed" || len(result.Ingest.IgnoredTransientFailedRuns) != 1 {
		t.Fatalf("health result = %#v, want legacy completed history to qualify transient failure", result)
	}
}

func TestCheckGraphHealthFailsZeroProjectionRun(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 5, 31, 12, 0, 0, 0, time.UTC)
	store := graphHealthFixtureStore(t, now)
	if err := store.PutIngestRun(ctx, graphstore.IngestRun{
		ID:                 "run-2",
		RuntimeID:          "azure-runtime",
		SourceID:           "azure",
		Status:             graphstore.IngestRunStatusCompleted,
		StartedAt:          now.Add(-time.Minute).Format(time.RFC3339Nano),
		FinishedAt:         now.Format(time.RFC3339Nano),
		EventsRead:         1,
		CheckpointComplete: true,
	}); err != nil {
		t.Fatalf("PutIngestRun(zero projection) error = %v", err)
	}

	result, err := checkGraphHealth(ctx, store, graphHealthOptions{
		IngestLimit:       10,
		MaxRunningMinutes: 60,
		RequiredRelations: []string{"belongs_to"},
	}, now)
	if err == nil {
		t.Fatal("checkGraphHealth() error = nil, want zero projection error")
	}
	if result.Status != "failed" || len(result.Ingest.ZeroProjectionRuns) != 1 || !strings.Contains(strings.Join(result.Failures, "; "), "projected no graph records") {
		t.Fatalf("health result = %#v, want zero projection failure", result)
	}
}

func TestCheckGraphHealthFailsIncompleteCheckpoint(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 5, 31, 12, 0, 0, 0, time.UTC)
	store := graphHealthFixtureStore(t, now)
	if err := store.PutIngestRun(ctx, graphstore.IngestRun{
		ID:                      "run-partial",
		RuntimeID:               "aws-runtime",
		SourceID:                "aws",
		Status:                  graphstore.IngestRunStatusCompleted,
		StartedAt:               now.Add(-time.Minute).Format(time.RFC3339Nano),
		FinishedAt:              now.Format(time.RFC3339Nano),
		EventsRead:              1,
		EntitiesProjected:       1,
		CheckpointComplete:      false,
		CheckpointCompleteKnown: true,
	}); err != nil {
		t.Fatalf("PutIngestRun(partial) error = %v", err)
	}

	result, err := checkGraphHealth(ctx, store, graphHealthOptions{
		IngestLimit:       10,
		MaxRunningMinutes: 60,
		RequiredRelations: []string{"belongs_to"},
	}, now)
	if err == nil {
		t.Fatal("checkGraphHealth() error = nil, want incomplete checkpoint error")
	}
	if result.Status != "failed" || len(result.Ingest.IncompleteRuns) != 1 || !strings.Contains(strings.Join(result.Failures, "; "), "has pages remaining") {
		t.Fatalf("health result = %#v, want incomplete checkpoint failure", result)
	}
}

func TestCheckGraphHealthExpandsLimitForDeclaredRuntimeIDs(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 5, 31, 12, 0, 0, 0, time.UTC)
	store := graphHealthFixtureStore(t, now)
	if err := store.PutIngestRun(ctx, graphstore.IngestRun{
		ID:                      "run-azure",
		RuntimeID:               "azure-runtime",
		SourceID:                "azure",
		Status:                  graphstore.IngestRunStatusCompleted,
		StartedAt:               now.Add(-2 * time.Minute).Format(time.RFC3339Nano),
		FinishedAt:              now.Add(-time.Minute).Format(time.RFC3339Nano),
		EventsRead:              1,
		EntitiesProjected:       1,
		LinksProjected:          1,
		CheckpointComplete:      true,
		CheckpointCompleteKnown: true,
	}); err != nil {
		t.Fatalf("PutIngestRun(azure) error = %v", err)
	}

	result, err := checkGraphHealth(ctx, store, graphHealthOptions{
		IngestLimit:        1,
		MaxRunningMinutes:  60,
		RequiredRelations:  []string{"belongs_to"},
		DeclaredRuntimeIDs: []string{"aws-runtime", "azure-runtime"},
	}, now)
	if err != nil {
		t.Fatalf("checkGraphHealth() error = %v", err)
	}
	if result.Ingest.CurrentRuntimeCount != 2 || len(result.Ingest.MissingRuntimeIDs) != 0 {
		t.Fatalf("ingest = %#v, want both declared runtimes current", result.Ingest)
	}
}

func TestParseGraphHealthArgs(t *testing.T) {
	options, err := parseGraphHealthArgs([]string{
		"ingest_limit=100",
		"max_running_minutes=15",
		"relations=belongs_to,represents,belongs_to",
		"report_relations=belongs_to,can_assume",
		"max_isolated_ratio=0.25",
		"declared_runtime_ids=aws-runtime, azure-runtime ",
		"allow_transient_source_failures=true",
	})
	if err != nil {
		t.Fatalf("parseGraphHealthArgs() error = %v", err)
	}
	if options.IngestLimit != 100 || options.MaxRunningMinutes != 15 || !options.AllowTransientSourceFailures {
		t.Fatalf("options = %#v, want parsed numeric and boolean fields", options)
	}
	if options.MaxIsolatedRatio != 0.25 {
		t.Fatalf("max_isolated_ratio = %v, want 0.25", options.MaxIsolatedRatio)
	}
	if !reflect.DeepEqual(options.ReportRelations, []string{"belongs_to", "can_assume"}) {
		t.Fatalf("report relations = %#v", options.ReportRelations)
	}
	if !reflect.DeepEqual(options.RequiredRelations, []string{"belongs_to", "represents"}) {
		t.Fatalf("relations = %#v", options.RequiredRelations)
	}
	if !reflect.DeepEqual(options.DeclaredRuntimeIDs, []string{"aws-runtime", "azure-runtime"}) {
		t.Fatalf("declared runtime ids = %#v", options.DeclaredRuntimeIDs)
	}
}

func graphHealthFixtureStore(t *testing.T, now time.Time) *graphTestStore {
	t.Helper()
	ctx := context.Background()
	store := newGraphTestStore()
	if err := store.UpsertProjectedEntity(ctx, &ports.ProjectedEntity{
		URN:        "urn:cerebro:writer:identity:alice",
		TenantID:   "writer",
		SourceID:   "test",
		EntityType: "identity",
		Label:      "alice",
	}); err != nil {
		t.Fatalf("UpsertProjectedEntity(identity) error = %v", err)
	}
	if err := store.UpsertProjectedEntity(ctx, &ports.ProjectedEntity{
		URN:        "urn:cerebro:writer:repository:repo",
		TenantID:   "writer",
		SourceID:   "test",
		EntityType: "repository",
		Label:      "repo",
	}); err != nil {
		t.Fatalf("UpsertProjectedEntity(repository) error = %v", err)
	}
	if err := store.UpsertProjectedLink(ctx, &ports.ProjectedLink{
		FromURN:   "urn:cerebro:writer:identity:alice",
		ToURN:     "urn:cerebro:writer:repository:repo",
		TenantID:  "writer",
		SourceID:  "test",
		Relation:  "belongs_to",
		RuntimeID: "aws-runtime",
	}); err != nil {
		t.Fatalf("UpsertProjectedLink() error = %v", err)
	}
	if err := store.PutIngestRun(ctx, graphstore.IngestRun{
		ID:                      "run-1",
		RuntimeID:               "aws-runtime",
		SourceID:                "aws",
		Status:                  graphstore.IngestRunStatusCompleted,
		StartedAt:               now.Add(-10 * time.Minute).Format(time.RFC3339Nano),
		FinishedAt:              now.Add(-9 * time.Minute).Format(time.RFC3339Nano),
		EventsRead:              1,
		EntitiesProjected:       1,
		LinksProjected:          1,
		CheckpointComplete:      true,
		CheckpointCompleteKnown: true,
	}); err != nil {
		t.Fatalf("PutIngestRun(completed) error = %v", err)
	}
	return store
}
