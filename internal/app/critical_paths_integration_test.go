package app

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/writer/cerebro/internal/events"
	"github.com/writer/cerebro/internal/executionstore"
	"github.com/writer/cerebro/internal/findings"
	"github.com/writer/cerebro/internal/graph"
	"github.com/writer/cerebro/internal/graph/builders"
	"github.com/writer/cerebro/internal/health"
	"github.com/writer/cerebro/internal/notifications"
	"github.com/writer/cerebro/internal/policy"
	"github.com/writer/cerebro/internal/remediation"
	"github.com/writer/cerebro/internal/runtime"
	"github.com/writer/cerebro/internal/testutil/integration"
	"github.com/writer/cerebro/internal/ticketing"
	"github.com/writer/cerebro/internal/webhooks"
)

type integrationGraphSource struct {
	mu          sync.Mutex
	latest      time.Time
	events      []map[string]any
	queryCounts map[string]int
}

func newIntegrationGraphSource() *integrationGraphSource {
	return &integrationGraphSource{queryCounts: make(map[string]int)}
}

func (s *integrationGraphSource) Query(_ context.Context, query string, _ ...any) (*builders.DataQueryResult, error) {
	lower := strings.ToLower(query)

	s.mu.Lock()
	defer s.mu.Unlock()

	if strings.Contains(lower, "select max(event_time)") && strings.Contains(lower, "from cdc_events") {
		s.queryCounts["has_changes"]++
		return &builders.DataQueryResult{Rows: []map[string]any{{"latest": s.latest}}, Count: 1}, nil
	}
	if strings.Contains(lower, "select event_id") && strings.Contains(lower, "from cdc_events") {
		s.queryCounts["cdc_events"]++
		rows := make([]map[string]any, 0, len(s.events))
		rows = append(rows, s.events...)
		return &builders.DataQueryResult{Rows: rows, Count: len(rows)}, nil
	}

	return &builders.DataQueryResult{Rows: []map[string]any{}}, nil
}

func (s *integrationGraphSource) setLatest(ts time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.latest = ts
}

func (s *integrationGraphSource) setEvents(events []map[string]any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = events
}

func integrationLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func newCriticalPathApp(t *testing.T) *App {
	t.Helper()

	stateDir := t.TempDir()
	cfg := &Config{
		LogLevel:           "error",
		ExecutionStoreFile: filepath.Join(stateDir, "executions.db"),
		GraphSnapshotPath:  filepath.Join(stateDir, "graph-snapshots"),
	}
	executionStore, err := executionstore.NewSQLiteStore(cfg.ExecutionStoreFile)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}

	application := &App{
		Config:         cfg,
		Logger:         integrationLogger(),
		Policy:         policy.NewEngine(),
		Findings:       findings.NewStore(),
		Notifications:  notifications.NewManager(),
		Ticketing:      ticketing.NewService(),
		Webhooks:       webhooks.NewServiceForTesting(),
		Remediation:    remediation.NewEngine(integrationLogger()),
		RuntimeRespond: runtime.NewResponseEngine(),
		SecurityGraph:  graph.New(),
		Health:         health.NewRegistry(),
		ExecutionStore: executionStore,
	}
	t.Cleanup(func() {
		_ = application.Close()
	})
	return application
}

func TestCriticalPath_SyncCDCGraphMaterializationRoundTrip(t *testing.T) {
	application := newCriticalPathApp(t)
	source := newIntegrationGraphSource()
	builder := builders.NewBuilder(source, integrationLogger())
	if err := builder.Build(context.Background()); err != nil {
		t.Fatalf("initial graph build failed: %v", err)
	}

	application.Logger = integrationLogger()
	application.SecurityGraphBuilder = builder
	application.SecurityGraph = builder.Graph()

	base := time.Date(2026, 3, 13, 14, 0, 0, 0, time.UTC)
	source.setLatest(base.Add(30 * time.Second))
	source.setEvents([]map[string]any{{
		"event_id":    "evt-cdc-1",
		"table_name":  "aws_s3_buckets",
		"resource_id": "arn:aws:s3:::integration-bucket",
		"change_type": "added",
		"provider":    "aws",
		"region":      "us-east-1",
		"account_id":  "111111111111",
		"payload": map[string]any{
			"arn":                 "arn:aws:s3:::integration-bucket",
			"name":                "integration-bucket",
			"account_id":          "111111111111",
			"region":              "us-east-1",
			"block_public_acls":   false,
			"block_public_policy": false,
		},
		"event_time": base.Add(30 * time.Second),
	}})

	summary, err := application.ApplySecurityGraphChanges(context.Background(), "integration_test")
	if err != nil {
		t.Fatalf("ApplySecurityGraphChanges: %v", err)
	}
	if summary.EventsProcessed != 1 {
		t.Fatalf("expected one CDC event processed, got %#v", summary)
	}
	if current := application.CurrentSecurityGraph(); current == nil {
		t.Fatal("expected active security graph")
	} else if _, ok := current.GetNode("arn:aws:s3:::integration-bucket"); !ok {
		t.Fatalf("expected incrementally materialized bucket node, got graph metadata %#v", current.Metadata())
	}
}

func TestCriticalPath_PolicyEvaluationToRemediationAction(t *testing.T) {
	application := newCriticalPathApp(t)
	application.Logger = integrationLogger()
	application.RuntimeRespond = runtime.NewResponseEngine()
	application.RemediationExecutor = remediation.NewExecutor(
		application.Remediation,
		application.Ticketing,
		application.Notifications,
		application.Findings,
		application.Webhooks,
	)

	application.Policy.AddPolicy(&policy.Policy{
		ID:          "no-public-buckets",
		Name:        "No Public Buckets",
		Description: "Buckets must not be public",
		Effect:      "forbid",
		Resource:    "aws::s3::bucket",
		Conditions:  []string{"resource.public == true"},
		Severity:    "critical",
	})

	if err := application.Remediation.AddRule(remediation.Rule{
		ID:          "resolve-public-bucket-finding",
		Name:        "Resolve public bucket finding",
		Description: "test-only integration rule",
		Enabled:     true,
		Trigger: remediation.Trigger{
			Type:     remediation.TriggerFindingCreated,
			PolicyID: "no-public-buckets",
		},
		Actions: []remediation.Action{{Type: remediation.ActionResolveFinding}},
	}); err != nil {
		t.Fatalf("AddRule: %v", err)
	}

	policyFindings, err := application.Policy.EvaluateAsset(context.Background(), map[string]any{
		"_cq_id":    "bucket-1",
		"_cq_table": "aws_s3_buckets",
		"type":      "aws::s3::bucket",
		"name":      "integration-bucket",
		"public":    true,
	})
	if err != nil {
		t.Fatalf("EvaluateAsset: %v", err)
	}
	if len(policyFindings) != 1 {
		t.Fatalf("expected one finding from policy evaluation, got %#v", policyFindings)
	}

	stored := application.upsertFindingAndRemediate(context.Background(), policyFindings[0])
	if stored == nil {
		t.Fatal("expected finding to be persisted")
		return
	}
	if got := strings.ToUpper(stored.Status); got != "RESOLVED" {
		t.Fatalf("expected remediation to resolve finding, got status %s", got)
	}
	if executions := application.Remediation.ListExecutions(20); len(executions) == 0 {
		t.Fatal("expected remediation execution record")
	}
}

func TestCriticalPath_JetStreamEventIngestToCorrelationEdgeMaterialization(t *testing.T) {
	natsURL := integration.StartJetStreamServer(t)
	application := newCriticalPathApp(t)
	application.Logger = integrationLogger()
	application.graphReady = make(chan struct{})
	close(application.graphReady)
	application.Config.NATSJetStreamEnabled = true
	application.Config.NATSJetStreamURLs = []string{natsURL}
	application.Config.NATSJetStreamConnectTimeout = 5 * time.Second
	application.Config.NATSJetStreamAuthMode = "none"
	application.Config.NATSConsumerEnabled = true
	application.Config.NATSConsumerStream = "ENSEMBLE_TAP"
	application.Config.NATSConsumerSubjects = []string{"ensemble.tap.>"}
	application.Config.NATSConsumerDurable = "critical_path_graph_builder"
	application.Config.NATSConsumerBatchSize = 10
	application.Config.NATSConsumerAckWait = 30 * time.Second
	application.Config.NATSConsumerFetchTimeout = 200 * time.Millisecond
	application.Config.NATSConsumerInProgressInterval = 5 * time.Second
	application.Config.NATSConsumerDrainTimeout = 5 * time.Second
	application.Config.NATSConsumerDeadLetterPath = filepath.Join(t.TempDir(), "nats-consumer.dlq.jsonl")
	application.Config.NATSConsumerDedupEnabled = true
	application.Config.NATSConsumerDedupStateFile = application.Config.ExecutionStoreFile
	application.Config.NATSConsumerDedupTTL = time.Hour
	application.Config.NATSConsumerDedupMaxRecords = 1000
	application.Config.NATSConsumerDropHealthLookback = 5 * time.Minute
	application.Config.NATSConsumerDropHealthThreshold = 1
	application.Config.NATSConsumerGraphStalenessThreshold = 15 * time.Minute

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	application.initTapGraphConsumer(ctx)
	if application.TapConsumer == nil {
		t.Fatal("expected tap consumer to initialize")
		return
	}
	defer func() {
		drainCtx, drainCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer drainCancel()
		_ = application.TapConsumer.Drain(drainCtx)
		_ = application.TapConsumer.Close()
	}()

	nc, err := nats.Connect(natsURL, nats.Timeout(2*time.Second))
	if err != nil {
		t.Fatalf("connect nats: %v", err)
	}
	defer nc.Close()
	js, err := nc.JetStream()
	if err != nil {
		t.Fatalf("jetstream context: %v", err)
	}

	base := time.Date(2026, 3, 13, 10, 0, 0, 0, time.UTC)
	for _, evt := range []events.CloudEvent{
		{
			ID:     "evt-pr-1",
			Source: "ensemble.tap.github",
			Type:   "ensemble.tap.github.pull_request.merged",
			Time:   base,
			Data: map[string]any{
				"repository":      "payments",
				"number":          42,
				"title":           "Fix checkout race",
				"merged_by":       "alice",
				"merged_by_email": "alice@example.com",
			},
		},
		{
			ID:     "evt-deploy-1",
			Source: "ensemble.tap.ci",
			Type:   "ensemble.tap.ci.deploy.completed",
			Time:   base.Add(5 * time.Minute),
			Data: map[string]any{
				"service":         "payments",
				"deploy_id":       "deploy-1",
				"environment":     "prod",
				"status":          "succeeded",
				"release_version": "2026.03.13.1",
				"actor_email":     "alice@example.com",
			},
		},
		{
			ID:     "evt-incident-1",
			Source: "ensemble.tap.incident",
			Type:   "ensemble.tap.incident.timeline.created",
			Time:   base.Add(7 * time.Minute),
			Data: map[string]any{
				"incident_id":  "inc-1",
				"service":      "payments",
				"event_id":     "evt-1",
				"status":       "open",
				"severity":     "high",
				"event_type":   "created",
				"title":        "Payments incident",
				"summary":      "Checkout latency spiked",
				"performed_at": base.Add(7 * time.Minute).Format(time.RFC3339),
				"actor_email":  "alice@example.com",
			},
		},
	} {
		payload, err := json.Marshal(evt)
		if err != nil {
			t.Fatalf("marshal %s: %v", evt.Type, err)
		}
		if _, err := js.Publish(evt.Type, payload); err != nil {
			t.Fatalf("publish %s: %v", evt.Type, err)
		}
	}

	waitForCondition(t, 5*time.Second, func() bool {
		incidentEdges := application.CurrentSecurityGraph().GetOutEdges("incident:inc-1")
		deployEdges := application.CurrentSecurityGraph().GetOutEdges("deployment:payments:deploy-1")
		return graphEdgeExists(incidentEdges, graph.EdgeKindCausedBy, "deployment:payments:deploy-1") &&
			graphEdgeExists(deployEdges, graph.EdgeKindTriggeredBy, "pull_request:payments:42")
	}, func() string {
		incidentEdges := application.CurrentSecurityGraph().GetOutEdges("incident:inc-1")
		deployEdges := application.CurrentSecurityGraph().GetOutEdges("deployment:payments:deploy-1")
		return "incident edges=" + formatEdges(incidentEdges) + " deploy edges=" + formatEdges(deployEdges)
	})
}

func waitForCondition(t *testing.T, timeout time.Duration, condition func() bool, describe func() string) {
	t.Helper()

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("condition not satisfied within %s: %s", timeout, describe())
}

func formatEdges(edges []*graph.Edge) string {
	parts := make([]string, 0, len(edges))
	for _, edge := range edges {
		if edge == nil {
			continue
		}
		parts = append(parts, string(edge.Kind)+":"+edge.Target)
	}
	return strings.Join(parts, ",")
}

func TestFormatEdgesSkipsNilEdges(t *testing.T) {
	t.Parallel()

	got := formatEdges([]*graph.Edge{
		nil,
		{Kind: graph.EdgeKindCausedBy, Target: "deployment:payments:deploy-1"},
	})
	if got != "caused_by:deployment:payments:deploy-1" {
		t.Fatalf("formatEdges() = %q, want %q", got, "caused_by:deployment:payments:deploy-1")
	}
}
