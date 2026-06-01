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

func TestCheckGraphHealthFailsZeroProjectionRun(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 5, 31, 12, 0, 0, 0, time.UTC)
	store := graphHealthFixtureStore(t, now)
	if err := store.PutIngestRun(ctx, graphstore.IngestRun{
		ID:         "run-2",
		RuntimeID:  "azure-runtime",
		SourceID:   "azure",
		Status:     graphstore.IngestRunStatusCompleted,
		StartedAt:  now.Add(-time.Minute).Format(time.RFC3339Nano),
		FinishedAt: now.Format(time.RFC3339Nano),
		EventsRead: 1,
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

func TestParseGraphHealthArgs(t *testing.T) {
	options, err := parseGraphHealthArgs([]string{
		"ingest_limit=100",
		"max_running_minutes=15",
		"relations=belongs_to,represents,belongs_to",
		"declared_runtime_ids=aws-runtime, azure-runtime ",
		"allow_transient_source_failures=true",
	})
	if err != nil {
		t.Fatalf("parseGraphHealthArgs() error = %v", err)
	}
	if options.IngestLimit != 100 || options.MaxRunningMinutes != 15 || !options.AllowTransientSourceFailures {
		t.Fatalf("options = %#v, want parsed numeric and boolean fields", options)
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
		ID:                "run-1",
		RuntimeID:         "aws-runtime",
		SourceID:          "aws",
		Status:            graphstore.IngestRunStatusCompleted,
		StartedAt:         now.Add(-10 * time.Minute).Format(time.RFC3339Nano),
		FinishedAt:        now.Add(-9 * time.Minute).Format(time.RFC3339Nano),
		EventsRead:        1,
		EntitiesProjected: 1,
		LinksProjected:    1,
	}); err != nil {
		t.Fatalf("PutIngestRun(completed) error = %v", err)
	}
	return store
}
