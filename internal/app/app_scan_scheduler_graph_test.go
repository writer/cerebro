package app

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/graph"
	"github.com/writer/cerebro/internal/webhooks"
)

type schedulerGraphSource struct {
	mu           sync.Mutex
	latest       time.Time
	events       []map[string]any
	queryCounts  map[string]int
	failCDCQuery bool
}

func newSchedulerGraphSource() *schedulerGraphSource {
	return &schedulerGraphSource{queryCounts: make(map[string]int)}
}

func (s *schedulerGraphSource) Query(ctx context.Context, query string, args ...any) (*graph.QueryResult, error) {
	_ = ctx
	_ = args
	lower := strings.ToLower(query)

	s.mu.Lock()
	defer s.mu.Unlock()

	if strings.Contains(lower, "select event_time") && strings.Contains(lower, "from cdc_events") && strings.Contains(lower, "limit 1") {
		s.queryCounts["has_changes"]++
		if s.latest.IsZero() {
			return &graph.QueryResult{Rows: []map[string]any{}}, nil
		}
		return &graph.QueryResult{Rows: []map[string]any{{"event_time": s.latest, "ingested_at": s.latest, "event_id": "evt-latest"}}, Count: 1}, nil
	}
	if strings.Contains(lower, "select event_id") && strings.Contains(lower, "from cdc_events") {
		s.queryCounts["cdc_events"]++
		if s.failCDCQuery {
			return nil, context.DeadlineExceeded
		}
		rows := make([]map[string]any, 0, len(s.events))
		rows = append(rows, s.events...)
		return &graph.QueryResult{Rows: rows, Count: len(rows)}, nil
	}

	return &graph.QueryResult{Rows: []map[string]any{}}, nil
}

func (s *schedulerGraphSource) setLatest(ts time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.latest = ts
}

func (s *schedulerGraphSource) setEvents(events []map[string]any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = events
}

func (s *schedulerGraphSource) resetCounts() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.queryCounts = make(map[string]int)
}

func (s *schedulerGraphSource) count(key string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.queryCounts[key]
}

type captureEventPublisher struct {
	mu     sync.Mutex
	events []webhooks.Event
}

func (c *captureEventPublisher) Publish(_ context.Context, event webhooks.Event) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = append(c.events, event)
	return nil
}

func (c *captureEventPublisher) Close() error {
	return nil
}

func (c *captureEventPublisher) all() []webhooks.Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	copied := make([]webhooks.Event, len(c.events))
	copy(copied, c.events)
	return copied
}

func TestInitScheduler_GraphRebuildSkipsWhenNoChanges(t *testing.T) {
	source := newSchedulerGraphSource()
	builder := graph.NewBuilder(source, schedulerDigestTestLogger())
	if err := builder.Build(context.Background()); err != nil {
		t.Fatalf("initial build failed: %v", err)
	}

	source.setLatest(time.Now().UTC().Add(-1 * time.Minute))

	publisher := &captureEventPublisher{}
	hooks := webhooks.NewServiceForTesting()
	hooks.SetEventPublisher(publisher)

	app := &App{
		Config:               &Config{},
		Logger:               schedulerDigestTestLogger(),
		Webhooks:             hooks,
		SecurityGraphBuilder: builder,
		SecurityGraph:        builder.Graph(),
	}
	app.setGraphBuildState(GraphBuildSuccess, builder.Graph().Metadata().BuiltAt, nil)
	app.initScheduler(context.Background())

	job, ok := app.Scheduler.GetJob("graph-rebuild")
	if !ok {
		t.Fatal("expected graph-rebuild job to exist")
	}

	source.resetCounts()
	if err := job.Handler(context.Background()); err != nil {
		t.Fatalf("graph-rebuild handler returned error: %v", err)
	}
	if snapshot := app.GraphBuildSnapshot(); snapshot.State != GraphBuildSuccess {
		t.Fatalf("expected graph build state success after no-op rebuild, got %#v", snapshot)
	}

	if source.count("has_changes") == 0 {
		t.Fatal("expected HasChanges query to execute")
	}
	if source.count("cdc_events") != 0 {
		t.Fatalf("expected no CDC event query when unchanged, got %d", source.count("cdc_events"))
	}
	if got := len(publisher.all()); got != 0 {
		t.Fatalf("expected no mutation events when unchanged, got %d", got)
	}
}

func TestInitScheduler_GraphRebuildAppliesIncrementalChangesAndEmitsMutation(t *testing.T) {
	source := newSchedulerGraphSource()
	builder := graph.NewBuilder(source, schedulerDigestTestLogger())
	if err := builder.Build(context.Background()); err != nil {
		t.Fatalf("initial build failed: %v", err)
	}

	base := time.Now().UTC()
	source.setLatest(base.Add(30 * time.Second))
	source.setEvents([]map[string]any{{
		"event_id":    "evt-1",
		"table_name":  "aws_s3_buckets",
		"resource_id": "arn:aws:s3:::cdc-bucket",
		"change_type": "added",
		"provider":    "aws",
		"region":      "us-east-1",
		"account_id":  "111111111111",
		"payload": map[string]any{
			"arn":                 "arn:aws:s3:::cdc-bucket",
			"name":                "cdc-bucket",
			"account_id":          "111111111111",
			"region":              "us-east-1",
			"block_public_acls":   false,
			"block_public_policy": false,
		},
		"event_time": base.Add(30 * time.Second),
	}})

	publisher := &captureEventPublisher{}
	hooks := webhooks.NewServiceForTesting()
	hooks.SetEventPublisher(publisher)

	app := &App{
		Config:               &Config{},
		Logger:               schedulerDigestTestLogger(),
		Webhooks:             hooks,
		SecurityGraphBuilder: builder,
		SecurityGraph:        builder.Graph(),
	}
	app.initScheduler(context.Background())

	job, ok := app.Scheduler.GetJob("graph-rebuild")
	if !ok {
		t.Fatal("expected graph-rebuild job to exist")
	}

	source.resetCounts()
	if err := job.Handler(context.Background()); err != nil {
		t.Fatalf("graph-rebuild handler returned error: %v", err)
	}

	if source.count("has_changes") == 0 {
		t.Fatal("expected HasChanges query to execute")
	}
	if source.count("cdc_events") == 0 {
		t.Fatal("expected CDC query to execute")
	}
	if _, ok := app.SecurityGraph.GetNode("arn:aws:s3:::cdc-bucket"); !ok {
		t.Fatal("expected incrementally added node in security graph")
	}
	if snapshot := app.GraphBuildSnapshot(); snapshot.State != GraphBuildSuccess {
		t.Fatalf("expected graph build state success after incremental update, got %#v", snapshot)
	}

	events := publisher.all()
	if len(events) != 1 {
		t.Fatalf("expected exactly one published event, got %d", len(events))
	}
	if events[0].Type != webhooks.EventGraphMutated {
		t.Fatalf("expected published event type %q, got %q", webhooks.EventGraphMutated, events[0].Type)
	}
	if got, _ := events[0].Data["mode"].(string); got != graph.GraphMutationModeIncremental {
		t.Fatalf("expected mutation mode %q, got %q", graph.GraphMutationModeIncremental, got)
	}
	if got, _ := events[0].Data["trigger"].(string); got != "scheduler_incremental" {
		t.Fatalf("expected trigger scheduler_incremental, got %q", got)
	}
	if got, _ := events[0].Data["events_processed"].(int); got != 1 {
		t.Fatalf("expected events_processed=1, got %v", events[0].Data["events_processed"])
	}
}

func TestRebuildSecurityGraphUpdatesGraphBuildState(t *testing.T) {
	source := newSchedulerGraphSource()
	builder := graph.NewBuilder(source, schedulerDigestTestLogger())
	if err := builder.Build(context.Background()); err != nil {
		t.Fatalf("initial build failed: %v", err)
	}

	app := &App{
		Config:               &Config{},
		Logger:               schedulerDigestTestLogger(),
		SecurityGraphBuilder: builder,
		SecurityGraph:        builder.Graph(),
	}
	app.setGraphBuildState(GraphBuildFailed, time.Now().UTC(), context.DeadlineExceeded)

	if err := app.RebuildSecurityGraph(context.Background()); err != nil {
		t.Fatalf("RebuildSecurityGraph returned error: %v", err)
	}

	if snapshot := app.GraphBuildSnapshot(); snapshot.State != GraphBuildSuccess {
		t.Fatalf("expected graph build state success after rebuild, got %#v", snapshot)
	}
}
